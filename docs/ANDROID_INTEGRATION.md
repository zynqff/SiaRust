# Android Native Integration Guide

For pure Android (Kotlin/Java) projects without Flutter.

---

## Setup

### 1. Copy .so files

```
app/
└── src/
    └── main/
        └── jniLibs/
            ├── arm64-v8a/libguardlib.so
            ├── armeabi-v7a/libguardlib.so
            └── x86_64/libguardlib.so
```

### 2. JNI wrapper

The `examples/android_java/GuardLib.kt` file wraps the C FFI using JNI.

Since Kotlin/Java cannot call C functions directly, you need a thin JNI bridge. Add this C file to your project:

**app/src/main/cpp/guard_jni.c**
```c
#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include "guardlib.h"

// guard_init — returns handle as long
JNIEXPORT jlong JNICALL
Java_com_yourapp_security_GuardLib_guard_1init(JNIEnv *env, jobject thiz) {
    GuardHandle* h = guard_init();
    return (jlong)(intptr_t)h;
}

// guard_destroy
JNIEXPORT void JNICALL
Java_com_yourapp_security_GuardLib_guard_1destroy(JNIEnv *env, jobject thiz, jlong handle) {
    guard_destroy((GuardHandle*)(intptr_t)handle);
}

// guard_verify_config
JNIEXPORT jstring JNICALL
Java_com_yourapp_security_GuardLib_guard_1verify_1config(
    JNIEnv *env, jobject thiz,
    jlong handle, jbyteArray json_bytes, jbyteArray sig_bytes)
{
    jsize json_len = (*env)->GetArrayLength(env, json_bytes);
    jsize sig_len  = (*env)->GetArrayLength(env, sig_bytes);

    jbyte* json_ptr = (*env)->GetByteArrayElements(env, json_bytes, NULL);
    jbyte* sig_ptr  = (*env)->GetByteArrayElements(env, sig_bytes, NULL);

    char* result = guard_verify_config(
        (GuardHandle*)(intptr_t)handle,
        (const uint8_t*)json_ptr, (size_t)json_len,
        (const uint8_t*)sig_ptr,  (size_t)sig_len
    );

    (*env)->ReleaseByteArrayElements(env, json_bytes, json_ptr, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, sig_bytes,  sig_ptr,  JNI_ABORT);

    if (result == NULL) return NULL;

    jstring jresult = (*env)->NewStringUTF(env, result);
    guard_free_string(result);
    return jresult;
}

// guard_validate_certificate
JNIEXPORT jint JNICALL
Java_com_yourapp_security_GuardLib_guard_1validate_1certificate(
    JNIEnv *env, jobject thiz,
    jlong handle, jbyteArray cert_der, jstring expected_fp)
{
    jsize cert_len = (*env)->GetArrayLength(env, cert_der);
    jbyte* cert_ptr = (*env)->GetByteArrayElements(env, cert_der, NULL);
    const char* fp_str = (*env)->GetStringUTFChars(env, expected_fp, NULL);

    int result = guard_validate_certificate(
        (GuardHandle*)(intptr_t)handle,
        (const uint8_t*)cert_ptr, (size_t)cert_len,
        fp_str
    );

    (*env)->ReleaseByteArrayElements(env, cert_der, cert_ptr, JNI_ABORT);
    (*env)->ReleaseStringUTFChars(env, expected_fp, fp_str);
    return result;
}

// guard_last_error
JNIEXPORT jstring JNICALL
Java_com_yourapp_security_GuardLib_guard_1last_1error(JNIEnv *env, jobject thiz) {
    char* err = guard_last_error();
    if (err == NULL) return NULL;
    jstring jerr = (*env)->NewStringUTF(env, err);
    guard_free_string(err);
    return jerr;
}

// guard_version
JNIEXPORT jstring JNICALL
Java_com_yourapp_security_GuardLib_guard_1version(JNIEnv *env, jobject thiz) {
    return (*env)->NewStringUTF(env, guard_version());
}
```

### 3. CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.22)
project(guardlib_jni)

# Import guardlib as pre-built
add_library(guardlib SHARED IMPORTED)
set_target_properties(guardlib PROPERTIES
    IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libguardlib.so"
)

# JNI bridge
add_library(guard_jni SHARED guard_jni.c)
target_include_directories(guard_jni PRIVATE ${CMAKE_SOURCE_DIR}/../../../../../../guardlib)
target_link_libraries(guard_jni guardlib log)
```

### 4. build.gradle

```gradle
android {
    defaultConfig {
        externalNativeBuild {
            cmake { cppFlags "-std=c++17" }
        }
    }
    externalNativeBuild {
        cmake { path "src/main/cpp/CMakeLists.txt" }
    }
}
```

---

## Usage in Activity

```kotlin
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.yourapp.security.GuardLib
import com.yourapp.security.GuardConfig
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class MainActivity : AppCompatActivity() {

    private var guardConfig: GuardConfig? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 1. Initialize GuardLib
        val result = GuardLib.initialize()
        result.onFailure { e ->
            showSecurityError(e.message ?: "Security check failed")
            return
        }

        // 2. Try to load cached config
        loadCachedConfig()

        // 3. Fetch fresh config in background
        lifecycleScope.launch {
            refreshConfig()
        }
    }

    private suspend fun refreshConfig() {
        val response = withContext(Dispatchers.IO) {
            try {
                val client = OkHttpClient()
                val configJson = client.newCall(
                    Request.Builder().url("https://your-cdn.com/config.json").build()
                ).execute().body?.string() ?: return@withContext null

                val sigB64 = client.newCall(
                    Request.Builder().url("https://your-cdn.com/config.sig").build()
                ).execute().body?.string() ?: return@withContext null

                GuardLib.verifyConfig(configJson, sigB64)
            } catch (e: Exception) {
                null
            }
        }

        if (response != null) {
            guardConfig = response
            saveConfig(response)
        }
    }

    private fun saveConfig(config: GuardConfig) {
        val masterKey = MasterKey.Builder(this)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        val prefs = EncryptedSharedPreferences.create(
            this, "guard_prefs", masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
        prefs.edit()
            .putString("api_url", config.apiUrl)
            .putString("api_fingerprint", config.apiFingerprint)
            .apply()
    }

    private fun loadCachedConfig() {
        // Load from EncryptedSharedPreferences (same setup as saveConfig)
        // ...
    }

    private fun showSecurityError(message: String) {
        AlertDialog.Builder(this)
            .setTitle("Security Error")
            .setMessage(message)
            .setPositiveButton("OK") { _, _ -> finish() }
            .setCancelable(false)
            .show()
    }
}
```

---

## ProGuard / R8

Add to `proguard-rules.pro`:
```
-keep class com.yourapp.security.GuardLib { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}
```
