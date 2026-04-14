// GuardLib.kt — Android/Kotlin JNI wrapper
//
// Place in: app/src/main/java/com/yourapp/security/GuardLib.kt
//
// Add to app/build.gradle:
//   android {
//       ...
//       sourceSets {
//           main { jniLibs.srcDirs = ['src/main/jniLibs'] }
//       }
//   }
//
// Place .so files in:
//   src/main/jniLibs/arm64-v8a/libguardlib.so
//   src/main/jniLibs/armeabi-v7a/libguardlib.so
//   src/main/jniLibs/x86_64/libguardlib.so

package com.yourapp.security

import android.util.Base64
import android.util.Log

object GuardLib {
    private const val TAG = "GuardLib"

    init {
        System.loadLibrary("guardlib")
    }

    // ── Native declarations ────────────────────────────────────────────────────

    private external fun guard_init(): Long
    private external fun guard_destroy(handle: Long)
    private external fun guard_verify_config(
        handle: Long,
        jsonBytes: ByteArray,
        sigBytes: ByteArray
    ): String?
    private external fun guard_validate_certificate(
        handle: Long,
        certDer: ByteArray,
        expectedFp: String
    ): Int
    private external fun guard_last_error(): String?
    private external fun guard_version(): String

    // ── State ──────────────────────────────────────────────────────────────────

    private var handle: Long = 0L

    val version: String get() = guard_version()

    // ── Public API ─────────────────────────────────────────────────────────────

    /**
     * Initialize GuardLib. Call once on app startup.
     *
     * @return Result.success on success, Result.failure with reason on detection.
     * WARNING: If self-integrity check fails, the process aborts (SIGABRT).
     */
    fun initialize(): Result<Unit> {
        val h = guard_init()
        return if (h != 0L) {
            handle = h
            Log.i(TAG, "Initialized. Version: ${guard_version()}")
            Result.success(Unit)
        } else {
            val err = guard_last_error() ?: "Unknown error"
            Log.e(TAG, "Init failed: $err")
            Result.failure(GuardException(err))
        }
    }

    /**
     * Verify signed config and extract api_url + api_fingerprint.
     *
     * @param configJson  Raw config.json string
     * @param sigBase64   Signature file content (base64)
     * @return GuardConfig on success, null on failure
     */
    fun verifyConfig(configJson: String, sigBase64: String): GuardConfig? {
        checkInitialized()

        val jsonBytes = configJson.toByteArray(Charsets.UTF_8)
        val sigBytes = try {
            Base64.decode(sigBase64.trim(), Base64.DEFAULT)
        } catch (e: Exception) {
            Log.e(TAG, "Invalid signature base64: $e")
            return null
        }

        val resultJson = guard_verify_config(handle, jsonBytes, sigBytes)
        if (resultJson == null) {
            Log.e(TAG, "verifyConfig failed: ${guard_last_error()}")
            return null
        }

        // Parse minimal JSON result
        return try {
            val apiUrl = extractJsonString(resultJson, "api_url") ?: return null
            val apiFingerprint = extractJsonString(resultJson, "api_fingerprint") ?: return null
            GuardConfig(apiUrl, apiFingerprint)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse result: $e")
            null
        }
    }

    /**
     * Validate certificate fingerprint.
     *
     * @param certDer    Raw DER bytes of server certificate
     * @param expectedFp Expected fingerprint (uppercase hex, colon-separated)
     * @return true if valid, false if mismatch or error
     */
    fun validateCertificate(certDer: ByteArray, expectedFp: String): Boolean {
        checkInitialized()
        return when (val r = guard_validate_certificate(handle, certDer, expectedFp)) {
            1    -> true
            0    -> { Log.w(TAG, "Certificate fingerprint mismatch"); false }
            else -> { Log.e(TAG, "validateCertificate error: ${guard_last_error()}"); false }
        }
    }

    /**
     * Create an OkHttpClient with certificate pinning via GuardLib.
     *
     * @param expectedFp Fingerprint from verified config
     */
    fun createPinnedOkHttpClient(expectedFp: String): okhttp3.OkHttpClient {
        checkInitialized()
        return okhttp3.OkHttpClient.Builder()
            .hostnameVerifier { _, _ -> true } // we do our own pinning
            .sslSocketFactory(
                createPinnedSSLSocketFactory(expectedFp),
                createTrustManager(expectedFp)
            )
            .build()
    }

    fun destroy() {
        if (handle != 0L) {
            guard_destroy(handle)
            handle = 0L
        }
    }

    // ── Private ────────────────────────────────────────────────────────────────

    private fun checkInitialized() {
        if (handle == 0L) throw IllegalStateException("GuardLib not initialized. Call initialize() first.")
    }

    private fun extractJsonString(json: String, key: String): String? {
        val pattern = Regex("\"$key\"\\s*:\\s*\"([^\"]*)\"")
        return pattern.find(json)?.groupValues?.get(1)
    }

    private fun createTrustManager(expectedFp: String) = object : javax.net.ssl.X509TrustManager {
        override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
        override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {
            if (chain.isEmpty()) throw javax.net.ssl.SSLException("Empty certificate chain")
            val cert = chain[0]
            val certDer = cert.encoded
            if (!validateCertificate(certDer, expectedFp)) {
                throw javax.net.ssl.SSLException("Certificate fingerprint validation failed")
            }
        }
    }

    private fun createPinnedSSLSocketFactory(expectedFp: String): javax.net.ssl.SSLSocketFactory {
        val trustManager = createTrustManager(expectedFp)
        val sslContext = javax.net.ssl.SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf(trustManager), null)
        return sslContext.socketFactory
    }
}

data class GuardConfig(val apiUrl: String, val apiFingerprint: String)
class GuardException(message: String) : Exception(message)
