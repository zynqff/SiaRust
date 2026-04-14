// guard_service.dart — GuardLib Flutter/Dart FFI Integration
//
// Drop this file into your Flutter project.
// Replaces the Dart-based PinningService with Rust-backed security.
//
// Requirements:
//   pubspec.yaml dependencies:
//     ffi: ^2.1.0
//     flutter_secure_storage: ^9.0.0
//     dio: ^5.0.0
//
// Place the compiled .so files in:
//   android/app/src/main/jniLibs/
//     arm64-v8a/libguardlib.so
//     armeabi-v7a/libguardlib.so
//     x86_64/libguardlib.so   (emulator)
//
// iOS: add libguardlib.a to Xcode project (see docs/iOS_INTEGRATION.md)

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

// ── FFI type definitions ──────────────────────────────────────────────────────

typedef GuardHandleOpaque = Opaque;

// guard_init
typedef _GuardInitNative = Pointer<GuardHandleOpaque> Function();
typedef _GuardInit = Pointer<GuardHandleOpaque> Function();

// guard_destroy
typedef _GuardDestroyNative = Void Function(Pointer<GuardHandleOpaque>);
typedef _GuardDestroy = void Function(Pointer<GuardHandleOpaque>);

// guard_verify_config
typedef _GuardVerifyConfigNative = Pointer<Utf8> Function(
    Pointer<GuardHandleOpaque>, Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr);
typedef _GuardVerifyConfig = Pointer<Utf8> Function(
    Pointer<GuardHandleOpaque>, Pointer<Uint8>, int, Pointer<Uint8>, int);

// guard_validate_certificate
typedef _GuardValidateCertNative = Int32 Function(
    Pointer<GuardHandleOpaque>, Pointer<Uint8>, IntPtr, Pointer<Utf8>);
typedef _GuardValidateCert = int Function(
    Pointer<GuardHandleOpaque>, Pointer<Uint8>, int, Pointer<Utf8>);

// guard_last_error
typedef _GuardLastErrorNative = Pointer<Utf8> Function();
typedef _GuardLastError = Pointer<Utf8> Function();

// guard_free_string
typedef _GuardFreeStringNative = Void Function(Pointer<Utf8>);
typedef _GuardFreeString = void Function(Pointer<Utf8>);

// guard_version
typedef _GuardVersionNative = Pointer<Utf8> Function();
typedef _GuardVersion = Pointer<Utf8> Function();

// ── Storage keys ──────────────────────────────────────────────────────────────

const _kStorageApiUrl = 'guard_api_url';
const _kStorageApiFingerprint = 'guard_api_fingerprint';
const _kConfigUrl = 'https://rayadv.ru/config.json';
const _kConfigSigUrl = 'https://rayadv.ru/config.sig';

// ── GuardService ──────────────────────────────────────────────────────────────

class GuardService {
  GuardService._();
  static final instance = GuardService._();

  late final DynamicLibrary _lib;
  late final _GuardInit _init;
  late final _GuardDestroy _destroy;
  late final _GuardVerifyConfig _verifyConfig;
  late final _GuardValidateCert _validateCert;
  late final _GuardLastError _lastError;
  late final _GuardFreeString _freeString;
  late final _GuardVersion _version;

  Pointer<GuardHandleOpaque>? _handle;
  final _storage = const FlutterSecureStorage();

  String? _trustedApiUrl;
  String? _trustedFingerprint;

  String? get trustedApiUrl => _trustedApiUrl;
  String? get trustedFingerprint => _trustedFingerprint;

  /// Initialize GuardLib. Must be called before any other method.
  /// Throws [GuardInitException] if root/Frida detected or library fails.
  /// NOTE: If library self-integrity fails, the process aborts (SIGABRT).
  Future<void> initialize() async {
    _loadLibrary();
    _bindFunctions();

    debugPrint('[Guard] Library version: ${_version().toDartString()}');

    // guard_init() — may abort() internally if tampered
    final handle = _init();
    if (handle == nullptr) {
      final err = _readLastError();
      throw GuardInitException(err ?? 'guard_init() returned null');
    }

    _handle = handle;
    debugPrint('[Guard] ✅ Initialized successfully');

    // Load previously saved values from SecureStorage
    _trustedApiUrl = await _storage.read(key: _kStorageApiUrl);
    _trustedFingerprint = await _storage.read(key: _kStorageApiFingerprint);
    debugPrint('[Guard] Cached: url=$_trustedApiUrl fp=$_trustedFingerprint');
  }

  /// Fetch config.json + config.sig and verify signature via Rust.
  /// On success, saves api_url and api_fingerprint to SecureStorage.
  /// Returns true on success, false on failure.
  Future<bool> fetchAndVerifyConfig() async {
    _assertInitialized();

    try {
      final dio = Dio(BaseOptions(
        connectTimeout: const Duration(seconds: 10),
        receiveTimeout: const Duration(seconds: 10),
      ));

      final results = await Future.wait([
        dio.get<String>(_kConfigUrl, options: Options(responseType: ResponseType.plain)),
        dio.get<String>(_kConfigSigUrl, options: Options(responseType: ResponseType.plain)),
      ]);

      final configRaw = results[0].data ?? '';
      final sigB64 = (results[1].data ?? '').trim();

      final configBytes = utf8.encode(configRaw);
      final sigBytes = base64.decode(sigB64); // decode from base64 → raw 64 bytes

      if (sigBytes.length != 64) {
        debugPrint('[Guard] ❌ Signature wrong length: ${sigBytes.length}');
        return false;
      }

      // Call Rust — 5 independent signature checks happen here
      final resultPtr = _callVerifyConfig(configBytes, sigBytes);
      if (resultPtr == nullptr) {
        final err = _readLastError();
        debugPrint('[Guard] ❌ Verify failed: $err');
        return false;
      }

      final resultJson = resultPtr.toDartString();
      _freeString(resultPtr);

      final parsed = jsonDecode(resultJson) as Map<String, dynamic>;
      final apiUrl = parsed['api_url'] as String?;
      final apiFingerprint = parsed['api_fingerprint'] as String?;

      if (apiUrl == null || apiFingerprint == null) {
        debugPrint('[Guard] ❌ Missing fields in result');
        return false;
      }

      // APPLICATION saves to SecureStorage — Rust never stores anything
      await Future.wait([
        _storage.write(key: _kStorageApiUrl, value: apiUrl),
        _storage.write(key: _kStorageApiFingerprint, value: apiFingerprint),
      ]);

      _trustedApiUrl = apiUrl;
      _trustedFingerprint = apiFingerprint;

      debugPrint('[Guard] ✅ Config verified. url=$apiUrl');
      return true;
    } catch (e) {
      debugPrint('[Guard] ❌ fetchAndVerifyConfig error: $e');
      return false;
    }
  }

  /// Apply certificate pinning to a Dio instance.
  /// Call this after fetchAndVerifyConfig() succeeds.
  void applyToDio(Dio dio) {
    _assertInitialized();

    (dio.httpClientAdapter as IOHttpClientAdapter).validateCertificate =
        (X509Certificate? cert, String host, int port) {
      if (cert == null) {
        debugPrint('[Guard] ❌ Null cert for $host:$port');
        return false;
      }

      final fp = _trustedFingerprint;
      if (fp == null) {
        debugPrint('[Guard] ❌ No fingerprint loaded, blocking $host');
        return false;
      }

      // Call Rust for SPKI SHA-256 computation and comparison
      final result = _callValidateCertificate(cert.der, fp);

      if (result == -1) {
        final err = _readLastError();
        debugPrint('[Guard] ❌ Internal error in validateCertificate: $err');
        return false;
      }

      if (result == 0) {
        debugPrint('[Guard] ❌ Fingerprint mismatch for $host');
        return false;
      }

      return true; // result == 1
    };
  }

  /// Destroy the GuardLib handle and release resources.
  void dispose() {
    if (_handle != null) {
      _destroy(_handle!);
      _handle = null;
    }
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  void _loadLibrary() {
    if (Platform.isAndroid) {
      _lib = DynamicLibrary.open('libguardlib.so');
    } else if (Platform.isIOS) {
      _lib = DynamicLibrary.process(); // static linked on iOS
    } else if (Platform.isMacOS) {
      _lib = DynamicLibrary.open('libguardlib.dylib');
    } else if (Platform.isLinux) {
      _lib = DynamicLibrary.open('libguardlib.so');
    } else if (Platform.isWindows) {
      _lib = DynamicLibrary.open('guardlib.dll');
    } else {
      throw UnsupportedError('GuardLib: unsupported platform');
    }
  }

  void _bindFunctions() {
    _init = _lib.lookupFunction<_GuardInitNative, _GuardInit>('guard_init');
    _destroy = _lib.lookupFunction<_GuardDestroyNative, _GuardDestroy>('guard_destroy');
    _verifyConfig = _lib.lookupFunction<_GuardVerifyConfigNative, _GuardVerifyConfig>('guard_verify_config');
    _validateCert = _lib.lookupFunction<_GuardValidateCertNative, _GuardValidateCert>('guard_validate_certificate');
    _lastError = _lib.lookupFunction<_GuardLastErrorNative, _GuardLastError>('guard_last_error');
    _freeString = _lib.lookupFunction<_GuardFreeStringNative, _GuardFreeString>('guard_free_string');
    _version = _lib.lookupFunction<_GuardVersionNative, _GuardVersion>('guard_version');
  }

  Pointer<Utf8> _callVerifyConfig(List<int> jsonBytes, List<int> sigBytes) {
    final jsonPtr = malloc.allocate<Uint8>(jsonBytes.length);
    final sigPtr = malloc.allocate<Uint8>(64);

    try {
      for (var i = 0; i < jsonBytes.length; i++) { jsonPtr[i] = jsonBytes[i]; }
      for (var i = 0; i < 64; i++) { sigPtr[i] = sigBytes[i]; }

      return _verifyConfig(_handle!, jsonPtr, jsonBytes.length, sigPtr, 64);
    } finally {
      malloc.free(jsonPtr);
      malloc.free(sigPtr);
    }
  }

  int _callValidateCertificate(Uint8List certDer, String expectedFp) {
    final certPtr = malloc.allocate<Uint8>(certDer.length);
    final fpPtr = expectedFp.toNativeUtf8();

    try {
      for (var i = 0; i < certDer.length; i++) { certPtr[i] = certDer[i]; }
      return _validateCert(_handle!, certPtr, certDer.length, fpPtr);
    } finally {
      malloc.free(certPtr);
      malloc.free(fpPtr);
    }
  }

  String? _readLastError() {
    final ptr = _lastError();
    if (ptr == nullptr) return null;
    final msg = ptr.toDartString();
    _freeString(ptr);
    return msg;
  }

  void _assertInitialized() {
    if (_handle == null) throw StateError('GuardService not initialized. Call initialize() first.');
  }
}

// ── Exceptions ────────────────────────────────────────────────────────────────

class GuardInitException implements Exception {
  final String message;
  GuardInitException(this.message);

  @override
  String toString() => 'GuardInitException: $message';
}
