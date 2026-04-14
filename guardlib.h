/*
 * guardlib.h — Public C API for GuardLib
 *
 * Include this header when integrating GuardLib into:
 *   - Android (JNI wrapper)
 *   - iOS (Swift/ObjC via bridging header)
 *   - Flutter (dart:ffi)
 *   - Python (ctypes / cffi)
 *   - Node.js (node-ffi-napi / napi)
 *   - Any C/C++ application
 *
 * Memory rules:
 *   - Strings returned by guard_verify_config() and guard_last_error()
 *     are heap-allocated by Rust. YOU MUST free them with guard_free_string().
 *   - Do NOT call free() or delete on Rust-allocated strings.
 *   - guard_version() returns a static pointer — do NOT free it.
 *   - GuardHandle* is freed by guard_destroy(), not by free().
 */

#ifndef GUARDLIB_H
#define GUARDLIB_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle — do not inspect or modify internals */
typedef struct GuardHandle GuardHandle;

/**
 * guard_init — Initialize GuardLib and run threat detection.
 *
 * Performs self-integrity check, Frida detection, and root/jailbreak detection.
 *
 * WARNING: If self-integrity check fails (code has been patched), this function
 * calls std::process::abort() — the process terminates immediately.
 * This cannot be caught by any exception handler.
 *
 * @return  Non-NULL GuardHandle* on success.
 *          NULL on detection or error — call guard_last_error() for reason.
 */
GuardHandle* guard_init(void);

/**
 * guard_destroy — Release resources associated with a GuardHandle.
 *
 * @param handle  Handle from guard_init(). Safe to call with NULL.
 */
void guard_destroy(GuardHandle* handle);

/**
 * guard_verify_config — Verify signed config and extract URL + fingerprint.
 *
 * Verifies the Ed25519 signature using 5 independent checks.
 * All 5 must pass. On success, returns a JSON string:
 *   {"api_url":"https://...","api_fingerprint":"AA:BB:CC:..."}
 *
 * The application is responsible for saving these values to secure storage.
 * GuardLib does NOT store anything.
 *
 * @param handle      From guard_init(). Must not be NULL.
 * @param json_ptr    UTF-8 config JSON bytes (not NUL-terminated).
 * @param json_len    Byte length of json_ptr.
 * @param sig_ptr     Raw 64-byte Ed25519 signature (NOT base64-encoded).
 * @param sig_len     Must be exactly 64.
 *
 * @return  Heap-allocated JSON C string on success. Caller MUST free with guard_free_string().
 *          NULL on failure — call guard_last_error() for reason.
 */
char* guard_verify_config(
    const GuardHandle* handle,
    const uint8_t*     json_ptr,
    size_t             json_len,
    const uint8_t*     sig_ptr,
    size_t             sig_len
);

/**
 * guard_validate_certificate — Validate HTTPS certificate fingerprint.
 *
 * Computes SPKI SHA-256 from DER cert bytes and compares with expected_fp.
 * Uses constant-time comparison to prevent timing attacks.
 *
 * @param handle        From guard_init(). Must not be NULL.
 * @param cert_der      Raw DER bytes of the server's certificate.
 * @param cert_der_len  Byte length of cert_der.
 * @param expected_fp   NUL-terminated, uppercase hex, colon-separated:
 *                      e.g. "AA:BB:CC:DD:EE:FF:..."
 *
 * @return   1 — fingerprint matches (connection is safe to proceed).
 *           0 — fingerprint does NOT match (abort the HTTPS connection).
 *          -1 — internal error (check guard_last_error()).
 */
int guard_validate_certificate(
    const GuardHandle* handle,
    const uint8_t*     cert_der,
    size_t             cert_der_len,
    const char*        expected_fp
);

/**
 * guard_last_error — Get the last error message (thread-local).
 *
 * @return  Heap-allocated C string, or NULL if no error.
 *          Caller MUST free with guard_free_string().
 */
char* guard_last_error(void);

/**
 * guard_free_string — Free a string returned by GuardLib.
 *
 * Use for strings from guard_verify_config() and guard_last_error().
 * Safe to call with NULL.
 *
 * @param ptr  Pointer to free. Must have been returned by GuardLib.
 */
void guard_free_string(char* ptr);

/**
 * guard_version — Get library version string.
 *
 * @return  Static C string (e.g. "1.0.0"). Do NOT free this pointer.
 */
const char* guard_version(void);

#ifdef __cplusplus
}
#endif

#endif /* GUARDLIB_H */
