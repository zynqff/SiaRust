# iOS Integration Guide

---

## Setup

### 1. Add GuardLib.xcframework to Xcode

1. Build for iOS: `./scripts/build_all.sh ios`
2. In Xcode: File → Add Files → select `dist/ios/GuardLib.xcframework`
3. In target settings → General → Frameworks, Libraries → confirm it's listed as **Embed & Sign** (for dynamic) or **Do Not Embed** (for static .a)

Since GuardLib is a static library, use **Do Not Embed**.

### 2. Add bridging header

If your project doesn't have one:
1. File → New → Header File → name it `YourApp-Bridging-Header.h`
2. Build Settings → Swift Compiler - General → Objective-C Bridging Header → set path
3. Add to the file:
```objc
#import "guardlib.h"
```

Alternatively, copy `guardlib.h` into your project directory.

### 3. Copy GuardLib.swift

Copy `examples/ios/GuardLib.swift` into your project.

---

## Usage

### AppDelegate.swift

```swift
import UIKit

@main
class AppDelegate: UIResponder, UIApplicationDelegate {

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {

        // Initialize GuardLib — may abort() if tampered
        do {
            try GuardLib.shared.initialize()
        } catch let error as GuardError {
            showSecurityBlock(reason: error.localizedDescription)
            return true
        } catch {
            showSecurityBlock(reason: error.localizedDescription)
            return true
        }

        // Fetch fresh config
        Task {
            await refreshConfig()
        }

        return true
    }

    private func refreshConfig() async {
        do {
            let configJson = try await fetchString("https://your-cdn.com/config.json")
            let sigB64     = try await fetchString("https://your-cdn.com/config.sig")

            guard let config = GuardLib.shared.verifyConfig(
                configJson: configJson, sigBase64: sigB64
            ) else {
                showSecurityBlock(reason: "Config verification failed")
                return
            }

            // Save to Keychain
            KeychainHelper.save(key: "api_url",         value: config.apiUrl)
            KeychainHelper.save(key: "api_fingerprint", value: config.apiFingerprint)

        } catch {
            // Use cached values if network fails
        }
    }

    private func fetchString(_ urlString: String) async throws -> String {
        let url = URL(string: urlString)!
        let (data, _) = try await URLSession.shared.data(from: url)
        return String(data: data, encoding: .utf8)!
    }

    private func showSecurityBlock(reason: String) {
        DispatchQueue.main.async {
            // Show blocking UI — navigate to error screen
        }
    }
}
```

### URLSession with certificate pinning

```swift
class PinnedURLSessionDelegate: NSObject, URLSessionDelegate {

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard let fp = KeychainHelper.load(key: "api_fingerprint") else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let disposition = GuardLib.shared.handleAuthChallenge(challenge, expectedFp: fp)
        let credential  = disposition == .useCredential
            ? URLCredential(trust: challenge.protectionSpace.serverTrust!)
            : nil

        completionHandler(disposition, credential)
    }
}

// Usage:
let session = URLSession(
    configuration: .default,
    delegate: PinnedURLSessionDelegate(),
    delegateQueue: nil
)
```

### Alamofire with certificate pinning

```swift
import Alamofire

class GuardEvaluator: ServerTrustEvaluating {
    func evaluate(_ trust: SecTrust, forHost host: String) throws {
        guard let cert = SecTrustGetCertificateAtIndex(trust, 0),
              let fp   = KeychainHelper.load(key: "api_fingerprint") else {
            throw AFError.serverTrustEvaluationFailed(reason: .noPublicKeysFound)
        }

        if !GuardLib.shared.validateCertificate(cert, expectedFp: fp) {
            throw AFError.serverTrustEvaluationFailed(reason: .publicKeyPinningFailed(
                host: host, trust: trust, pinnedKeys: [], serverKeys: []
            ))
        }
    }
}

let evaluators: [String: ServerTrustEvaluating] = [
    "your-backend.com": GuardEvaluator()
]

let session = Session(
    serverTrustManager: ServerTrustManager(evaluators: evaluators)
)
```

---

## Simple Keychain helper

```swift
struct KeychainHelper {
    static func save(key: String, value: String) {
        let data = value.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String:   data,
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }

    static func load(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String:  true,
            kSecMatchLimit as String:  kSecMatchLimitOne,
        ]
        var result: AnyObject?
        SecItemCopyMatching(query as CFDictionary, &result)
        guard let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
```

---

## App Store considerations

- GuardLib uses no private APIs
- No dynamic frameworks — static `.a` / XCFramework only
- No network calls from within the library
- Passes App Store review guidelines

---

## Troubleshooting

**`Undefined symbol: _guard_init`**
→ guardlib.h not found or .a not linked. Check bridging header path and Build Phases.

**App crashes immediately on first launch**
→ Self-integrity check triggered (code patched). Set `INTEGRITY_CHECK_DISABLED = true` during development.

**Certificate pinning fails for all requests**
→ Fingerprint is stale after certificate renewal. Update config.json and re-sign.

**Simulator build fails**
→ Ensure you built the simulator slice: `cargo build --release --target aarch64-apple-ios-sim`
