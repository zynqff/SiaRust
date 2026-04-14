# Flutter Integration Guide

## Overview

GuardLib integrates into Flutter via `dart:ffi`. The `guard_service.dart` file in `examples/flutter/` replaces your existing Dart-based `PinningService` with a Rust-backed implementation.

---

## Prerequisites

- Flutter 3.x+
- Android NDK (for Android builds)
- Xcode 14+ (for iOS builds)

Add to `pubspec.yaml`:
```yaml
dependencies:
  ffi: ^2.1.0
  flutter_secure_storage: ^9.0.0
  dio: ^5.0.0
```

---

## Android Setup

### 1. Copy .so files

```
your_flutter_project/
└── android/
    └── app/
        └── src/
            └── main/
                └── jniLibs/
                    ├── arm64-v8a/
                    │   └── libguardlib.so     ← from dist/android/jniLibs/arm64-v8a/
                    ├── armeabi-v7a/
                    │   └── libguardlib.so
                    └── x86_64/
                        └── libguardlib.so     ← for emulator
```

### 2. android/app/build.gradle

Ensure `minSdk` is 21 or higher (GuardLib uses API 21 NDK linkers):

```gradle
android {
    defaultConfig {
        minSdkVersion 21
    }
}
```

### 3. Verify packaging

In `android/app/build.gradle`, confirm .so files are packaged:
```gradle
android {
    packagingOptions {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}
```

---

## iOS Setup

### 1. Add the XCFramework

Drag `dist/ios/GuardLib.xcframework` into your Xcode project.

In Build Phases → Link Binary With Libraries, confirm `GuardLib.xcframework` is listed.

### 2. Bridging header (if using Swift)

If you don't already have a bridging header:
1. Add a new `.h` file to the project (e.g. `Runner-Bridging-Header.h`)
2. Set it in Build Settings → Swift Compiler → Objective-C Bridging Header
3. Add:
```objc
#import "guardlib.h"
```

### 3. iOS note on DynamicLibrary.process()

On iOS, `dart:ffi` loads statically linked libraries via `DynamicLibrary.process()`.
The `guard_service.dart` already handles this:
```dart
} else if (Platform.isIOS) {
    _lib = DynamicLibrary.process();
}
```

---

## Integration

### 1. Copy guard_service.dart

Copy `examples/flutter/guard_service.dart` into your project, e.g.:
```
lib/services/guard_service.dart
```

### 2. Initialize in main.dart

```dart
import 'services/guard_service.dart';

void main() async {
    WidgetsFlutterBinding.ensureInitialized();

    try {
        await GuardService.instance.initialize();
    } on GuardInitException catch (e) {
        // Root or Frida detected — show error and block user
        runApp(SecurityErrorApp(message: e.message));
        return;
    }

    // Fetch and verify config on first launch (or periodically)
    final configOk = await GuardService.instance.fetchAndVerifyConfig();
    if (!configOk) {
        runApp(const SecurityErrorApp(message: 'Не удалось установить безопасное соединение'));
        return;
    }

    runApp(const MyApp());
}
```

### 3. Create your Dio client

```dart
import 'package:dio/dio.dart';
import 'services/guard_service.dart';

Dio createSecureDio() {
    final dio = Dio(BaseOptions(baseUrl: GuardService.instance.trustedApiUrl!));
    GuardService.instance.applyToDio(dio);  // applies certificate pinning
    return dio;
}
```

### 4. Handle certificate pinning errors

When `applyToDio()` is applied, Dio will throw a `DioException` if the certificate does not match. Handle it:

```dart
try {
    final response = await _dio.get('/endpoint');
} on DioException catch (e) {
    if (e.type == DioExceptionType.connectionError) {
        // Could be certificate mismatch
        showError('Ошибка безопасности. Сервер не прошёл проверку.');
    }
}
```

---

## Config refresh strategy

GuardLib does not manage config refresh. Recommended approach:

```dart
class AppStartup {
    static Future<bool> run() async {
        // Always try fresh config on startup
        final fresh = await GuardService.instance.fetchAndVerifyConfig();
        if (fresh) return true;

        // Fall back to cached values if network unavailable
        if (GuardService.instance.trustedApiUrl != null &&
            GuardService.instance.trustedFingerprint != null) {
            return true; // use cached
        }

        return false; // no config available at all
    }
}
```

---

## Error messages (user-facing)

| Scenario | Suggested message (RU) |
|---|---|
| `guard_init()` NULL (root/Frida) | «Это устройство не поддерживается по соображениям безопасности» |
| `fetchAndVerifyConfig()` false | «Не удалось установить безопасное соединение. Попробуйте позже» |
| Certificate mismatch (DioException) | «Ошибка безопасности. Сервер не прошёл проверку» |
| Process aborted (SIGABRT) | App crash — no UI possible |

---

## Troubleshooting

**`UnsatisfiedLinkError: dlopen failed: libguardlib.so`**
→ .so file not in jniLibs for the correct ABI. Check arm64-v8a vs armeabi-v7a.

**`Invalid argument(s): Failed to lookup symbol 'guard_init'`**
→ Wrong library loaded (wrong platform or wrong file). Check `_loadLibrary()`.

**App crashes immediately on `guard_init()`**
→ This is the self-integrity check triggering. It means the binary has been modified since you set `EXPECTED_HASH`. Rebuild the library and recompute the hash. During development, set `INTEGRITY_CHECK_DISABLED = true` in `src/integrity.rs`.

**Certificate pinning blocks all requests**
→ Your fingerprint may be stale. Re-run `scripts/get_fingerprint.py` and update config.json + re-sign.
