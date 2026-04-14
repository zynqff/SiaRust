// GuardLib.swift — iOS/macOS Swift wrapper for GuardLib
//
// Setup:
//   1. Add libguardlib.a to your Xcode target (Build Phases → Link Binary With Libraries)
//   2. Add guardlib.h to your Bridging Header:
//      #import "guardlib.h"
//   3. Add libguardlib.a and guardlib.h to your project navigator
//
// Note: On iOS, the library must be a static library (.a), not .dylib,
// because App Store does not allow embedded dynamic libraries from non-Apple SDKs.
// Build with: cargo build --release --target aarch64-apple-ios

import Foundation
import Security

// MARK: - GuardLib

public class GuardLib {
    public static let shared = GuardLib()
    private var handle: OpaquePointer?

    private init() {}

    // MARK: - Public API

    /// Initialize GuardLib and run threat detection.
    ///
    /// - Throws: `GuardError.initFailed` if root/Frida detected.
    /// - Warning: If self-integrity fails, the process aborts (SIGABRT).
    public func initialize() throws {
        let h = guard_init()
        guard let h = h else {
            let reason = lastError() ?? "Unknown error"
            throw GuardError.initFailed(reason)
        }
        handle = h
        let version = String(cString: guard_version())
        print("[GuardLib] ✅ Initialized. Version: \(version)")
    }

    /// Verify signed config and return api_url + api_fingerprint.
    ///
    /// - Parameters:
    ///   - configJson: Raw string content of config.json
    ///   - sigBase64: Raw string content of config.sig (base64)
    /// - Returns: GuardConfig on success, nil on failure
    public func verifyConfig(configJson: String, sigBase64: String) -> GuardConfig? {
        guard let h = handle else { fatalError("GuardLib not initialized") }

        guard let jsonData = configJson.data(using: .utf8) else { return nil }

        let trimmedSig = sigBase64.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let sigData = Data(base64Encoded: trimmedSig), sigData.count == 64 else {
            print("[GuardLib] ❌ Invalid signature")
            return nil
        }

        let resultPtr: UnsafeMutablePointer<CChar>? = jsonData.withUnsafeBytes { jsonRaw in
            sigData.withUnsafeBytes { sigRaw in
                guard let jsonPtr = jsonRaw.baseAddress?.assumingMemoryBound(to: UInt8.self),
                      let sigPtr = sigRaw.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return nil
                }
                return guard_verify_config(h, jsonPtr, jsonData.count, sigPtr, 64)
            }
        }

        guard let resultPtr = resultPtr else {
            print("[GuardLib] ❌ verifyConfig failed: \(lastError() ?? "unknown")")
            return nil
        }

        let resultJson = String(cString: resultPtr)
        guard_free_string(resultPtr)

        return parseGuardConfig(from: resultJson)
    }

    /// Validate a server certificate against a known fingerprint.
    ///
    /// - Parameters:
    ///   - secCertificate: The server certificate from URLSession challenge
    ///   - expectedFp: Expected SPKI SHA-256 fingerprint (uppercase, colon-separated)
    /// - Returns: true if valid, false to abort connection
    public func validateCertificate(_ secCertificate: SecCertificate, expectedFp: String) -> Bool {
        guard let h = handle else { fatalError("GuardLib not initialized") }

        let certData = SecCertificateCopyData(secCertificate) as Data

        let result: Int32 = certData.withUnsafeBytes { certRaw in
            guard let certPtr = certRaw.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return -1
            }
            return expectedFp.withCString { fpPtr in
                guard_validate_certificate(h, certPtr, certData.count, fpPtr)
            }
        }

        switch result {
        case 1:  return true
        case 0:  print("[GuardLib] ❌ Certificate fingerprint mismatch"); return false
        default: print("[GuardLib] ❌ Internal error: \(lastError() ?? "unknown")"); return false
        }
    }

    /// Use in URLSession delegate to enforce certificate pinning.
    ///
    /// Usage:
    ///   func urlSession(_ session: URLSession,
    ///                   didReceive challenge: URLAuthenticationChallenge,
    ///                   completionHandler: ...) {
    ///     let disposition = GuardLib.shared.handleAuthChallenge(challenge, expectedFp: trustedFp)
    ///     completionHandler(disposition, nil)
    ///   }
    public func handleAuthChallenge(
        _ challenge: URLAuthenticationChallenge,
        expectedFp: String
    ) -> URLSession.AuthChallengeDisposition {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            return .cancelAuthenticationChallenge
        }

        guard let cert = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            return .cancelAuthenticationChallenge
        }

        return validateCertificate(cert, expectedFp: expectedFp)
            ? .useCredential
            : .cancelAuthenticationChallenge
    }

    public func destroy() {
        if let h = handle {
            guard_destroy(h)
            handle = nil
        }
    }

    // MARK: - Private

    private func lastError() -> String? {
        guard let ptr = guard_last_error() else { return nil }
        let msg = String(cString: ptr)
        guard_free_string(ptr)
        return msg
    }

    private func parseGuardConfig(from json: String) -> GuardConfig? {
        guard let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: String],
              let apiUrl = obj["api_url"],
              let apiFingerprint = obj["api_fingerprint"],
              !apiUrl.isEmpty, !apiFingerprint.isEmpty else {
            return nil
        }
        return GuardConfig(apiUrl: apiUrl, apiFingerprint: apiFingerprint)
    }
}

// MARK: - Models

public struct GuardConfig {
    public let apiUrl: String
    public let apiFingerprint: String
}

public enum GuardError: Error {
    case initFailed(String)
    case notInitialized

    public var localizedDescription: String {
        switch self {
        case .initFailed(let r): return "GuardLib init failed: \(r)"
        case .notInitialized:    return "GuardLib not initialized"
        }
    }
}
