"""
guardlib_python.py — Python integration for GuardLib (server-side use)

Usage:
    from guardlib_python import GuardLib, GuardConfig

    guard = GuardLib()
    guard.initialize()

    with open("config.json") as f:
        config_json = f.read()
    with open("config.sig") as f:
        sig_b64 = f.read().strip()

    config = guard.verify_config(config_json, sig_b64)
    if config:
        print(f"API URL: {config.api_url}")
        print(f"Fingerprint: {config.api_fingerprint}")

Requirements:
    - Linux: libguardlib.so in same directory or LD_LIBRARY_PATH
    - macOS: libguardlib.dylib
    - Windows: guardlib.dll
"""

import ctypes
import base64
import json
import platform
import os
from dataclasses import dataclass
from typing import Optional


def _load_library() -> ctypes.CDLL:
    system = platform.system()
    names = {
        "Linux":   "libguardlib.so",
        "Darwin":  "libguardlib.dylib",
        "Windows": "guardlib.dll",
    }
    lib_name = names.get(system)
    if not lib_name:
        raise OSError(f"Unsupported platform: {system}")

    search_paths = [
        os.path.join(os.path.dirname(__file__), lib_name),
        lib_name,
    ]
    for path in search_paths:
        try:
            return ctypes.CDLL(path)
        except OSError:
            continue
    raise OSError(f"Cannot find {lib_name}. Place it next to this script.")


@dataclass
class GuardConfig:
    api_url: str
    api_fingerprint: str


class GuardLibException(Exception):
    pass


class GuardLib:
    def __init__(self):
        self._lib = _load_library()
        self._handle = None
        self._bind_functions()

    def _bind_functions(self):
        lib = self._lib

        lib.guard_init.restype = ctypes.c_void_p
        lib.guard_init.argtypes = []

        lib.guard_destroy.restype = None
        lib.guard_destroy.argtypes = [ctypes.c_void_p]

        lib.guard_verify_config.restype = ctypes.c_char_p
        lib.guard_verify_config.argtypes = [
            ctypes.c_void_p,      # handle
            ctypes.c_char_p,      # json_ptr
            ctypes.c_size_t,      # json_len
            ctypes.c_char_p,      # sig_ptr
            ctypes.c_size_t,      # sig_len
        ]

        lib.guard_validate_certificate.restype = ctypes.c_int
        lib.guard_validate_certificate.argtypes = [
            ctypes.c_void_p,  # handle
            ctypes.c_char_p,  # cert_der
            ctypes.c_size_t,  # cert_der_len
            ctypes.c_char_p,  # expected_fp
        ]

        lib.guard_last_error.restype = ctypes.c_char_p
        lib.guard_last_error.argtypes = []

        lib.guard_free_string.restype = None
        lib.guard_free_string.argtypes = [ctypes.c_char_p]

        lib.guard_version.restype = ctypes.c_char_p
        lib.guard_version.argtypes = []

    def initialize(self):
        """Initialize GuardLib. Raises GuardLibException on failure."""
        version = self._lib.guard_version().decode()
        print(f"[GuardLib] Version: {version}")

        handle = self._lib.guard_init()
        if not handle:
            err = self._last_error()
            raise GuardLibException(f"guard_init failed: {err}")

        self._handle = handle
        print("[GuardLib] ✅ Initialized")

    def verify_config(self, config_json: str, sig_base64: str) -> Optional[GuardConfig]:
        """Verify signed config and return GuardConfig or None."""
        self._assert_initialized()

        json_bytes = config_json.encode("utf-8")
        try:
            sig_bytes = base64.b64decode(sig_base64.strip())
        except Exception as e:
            print(f"[GuardLib] Invalid base64 signature: {e}")
            return None

        if len(sig_bytes) != 64:
            print(f"[GuardLib] Signature wrong length: {len(sig_bytes)}")
            return None

        result_ptr = self._lib.guard_verify_config(
            self._handle,
            json_bytes, len(json_bytes),
            sig_bytes, len(sig_bytes),
        )

        if not result_ptr:
            err = self._last_error()
            print(f"[GuardLib] ❌ verify_config failed: {err}")
            return None

        result_json = result_ptr.decode("utf-8")
        self._lib.guard_free_string(result_ptr)

        try:
            parsed = json.loads(result_json)
            return GuardConfig(
                api_url=parsed["api_url"],
                api_fingerprint=parsed["api_fingerprint"],
            )
        except (KeyError, json.JSONDecodeError) as e:
            print(f"[GuardLib] Failed to parse result: {e}")
            return None

    def validate_certificate(self, cert_der: bytes, expected_fp: str) -> bool:
        """Validate certificate fingerprint. Returns True if valid."""
        self._assert_initialized()
        result = self._lib.guard_validate_certificate(
            self._handle,
            cert_der, len(cert_der),
            expected_fp.encode("utf-8"),
        )
        if result == 1:
            return True
        elif result == 0:
            return False
        else:
            err = self._last_error()
            print(f"[GuardLib] Internal error in validate_certificate: {err}")
            return False

    def destroy(self):
        if self._handle:
            self._lib.guard_destroy(self._handle)
            self._handle = None

    def __del__(self):
        self.destroy()

    def _last_error(self) -> str:
        ptr = self._lib.guard_last_error()
        if not ptr:
            return "no error"
        msg = ptr.decode("utf-8")
        self._lib.guard_free_string(ptr)
        return msg

    def _assert_initialized(self):
        if not self._handle:
            raise GuardLibException("GuardLib not initialized. Call initialize() first.")
