# GuardLib

**Cryptographic config verification and certificate pinning — Rust FFI library**

GuardLib is a compiled security library that runs inside your application. It verifies that your backend configuration has not been tampered with, pins HTTPS connections to your server's certificate, and detects common runtime attacks (Frida, root, jailbreak).

All cryptographic operations run in compiled Rust code. GuardLib never makes network requests, never stores data, and never terminates your application — it returns results, and your application decides what to do.

---

## What GuardLib does

| Function | What it does |
|---|---|
| `guard_init()` | Detects Frida, root, jailbreak, and verifies its own code integrity |
| `guard_verify_config()` | Verifies Ed25519 signature of your config JSON using 5 independent checks |
| `guard_validate_certificate()` | Validates HTTPS certificate SPKI SHA-256 fingerprint |
| `guard_last_error()` | Returns the reason for the last failure |

---

## How it works

```
Your CDN / GitHub Pages
  config.json  ←──── signed with your private key (offline, never on server)
  config.sig

Your Application
  1. guard_init()                  → detect threats, verify self-integrity
  2. Download config.json + .sig   → your app (plain HTTPS, any HTTP client)
  3. guard_verify_config()         → 5× Ed25519 checks inside Rust
  4. App saves api_url + fp        → SecureStorage (your app does this)
  5. guard_validate_certificate()  → every HTTPS request to your backend
```

GuardLib does not know your CDN URL. GuardLib does not make network requests.
Your app downloads the files; GuardLib only verifies them.

---

## Security design

**Rust never makes decisions — it only reports results.**

The only exception: if GuardLib detects that its own code has been patched in memory, it calls `std::process::abort()`. This cannot be caught by Flutter, Java, Swift, or any exception handler. The process terminates with SIGABRT.

All other results are returned as values. Your application handles them.

| Scenario | GuardLib returns | Your app should |
|---|---|---|
| Root or Frida detected | `guard_init()` → NULL | Show error, block user |
| Config signature invalid | `guard_verify_config()` → NULL | Show error, block user |
| Certificate mismatch | `guard_validate_certificate()` → 0 | Abort HTTPS connection |
| Internal error | NULL or -1 | Treat as failure |
| Self-integrity tampered | `abort()` — no return | Process crashes (SIGABRT) |

**Signature verification:**
The Ed25519 public key is split into 5 parts, each XOR-obfuscated with a unique mask. Reconstruction and verification happen 5 times using 5 separate code paths. All 5 must return true. The `&` operator (not `&&`) ensures no short-circuit evaluation — all checks execute regardless.

---

## Supported platforms

| Platform | Output | Architecture |
|---|---|---|
| Android | `libguardlib.so` | arm64-v8a, armeabi-v7a, x86_64 |
| iOS | `libguardlib.a` / `GuardLib.xcframework` | arm64 (device + simulator) |
| Linux | `libguardlib.so` | x86_64 |
| macOS | `libguardlib.dylib` | arm64, x86_64 |
| Windows | `guardlib.dll` | x86_64 |

---

## Quick start

### Step 1 — Generate your key pair

```bash
cargo run --example keygen
```

This prints:
- Your **private key** (base64) — keep this secret, use it to sign configs
- Your **public key** (base64) — embed this in GuardLib

### Step 2 — Embed your public key

Open `src/crypto.rs`. Replace the `KEY_PART_*` and `MASK_*` constants with the values printed by `keygen`. The keygen tool prints ready-to-paste Rust constants.

### Step 3 — Build the library

```bash
# Host only (test)
./scripts/build_all.sh host

# Android
export ANDROID_NDK_HOME=/path/to/ndk
./scripts/setup_android_linkers.sh
./scripts/build_all.sh android

# iOS (macOS only)
./scripts/build_all.sh ios

# All platforms
./scripts/build_all.sh all
```

Output goes to `dist/`.

### Step 4 — Sign your config

Create `config.json`:
```json
{
  "api_url": "https://your-backend.com",
  "api_fingerprint": "AA:BB:CC:DD:EE:FF:..."
}
```

Sign it:
```bash
cargo run --example sign_config -- <your_private_key_base64> config.json
```

This produces `config.sig`. Upload both files to your CDN or GitHub Pages.

### Step 5 — Integrate

See `examples/` for your platform:

| Platform | File |
|---|---|
| Flutter | `examples/flutter/guard_service.dart` |
| Android/Kotlin | `examples/android_java/GuardLib.kt` |
| iOS/Swift | `examples/ios/GuardLib.swift` |
| Python | `examples/python/guardlib_python.py` |
| Node.js | `examples/node/guardlib_node.js` |

---

## Getting the certificate fingerprint

You need the SPKI SHA-256 fingerprint of your backend server's TLS certificate.

**Using OpenSSL:**
```bash
openssl s_client -connect your-backend.com:443 </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -hex \
  | sed 's/.*= //' \
  | tr '[:lower:]' '[:upper:]' \
  | sed 's/../&:/g;s/:$//'
```

**Using Python:**
```python
import ssl, hashlib, socket

hostname = 'your-backend.com'
ctx = ssl.create_default_context()
with socket.create_connection((hostname, 443)) as sock:
    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
        cert_der = ssock.getpeercert(binary_form=True)

import subprocess
result = subprocess.run(
    ['openssl', 'x509', '-pubkey', '-noout'],
    input=cert_der, capture_output=True
)
# ... see scripts/get_fingerprint.py for full script
```

Or use the provided helper:
```bash
python3 scripts/get_fingerprint.py your-backend.com
```

---

## Memory management

GuardLib allocates strings in Rust's heap. You must free them using `guard_free_string()`.

| Function | Returns | Free with |
|---|---|---|
| `guard_verify_config()` | `char*` (heap) | `guard_free_string()` |
| `guard_last_error()` | `char*` (heap) | `guard_free_string()` |
| `guard_version()` | `char*` (static) | **do NOT free** |

**Never call `free()` or `delete` on strings from GuardLib.** Always use `guard_free_string()`.

---

## Self-integrity setup

After building your release binary, compute its integrity hash and embed it:

```bash
./scripts/compute_integrity_hash.sh dist/android/jniLibs/arm64-v8a/libguardlib.so
```

This prints a `[u8; 32]` array. Replace `EXPECTED_HASH` in `src/integrity.rs` and set `INTEGRITY_CHECK_DISABLED = false`. Rebuild.

See `docs/INTEGRITY_SETUP.md` for the full workflow.

---

## Files in this package

```
guardlib/
├── src/
│   ├── lib.rs          — Crate root
│   ├── ffi.rs          — C-compatible FFI API (guard_init, guard_verify_config, ...)
│   ├── crypto.rs       — Ed25519 verification (5×), SPKI SHA-256, key reconstruction
│   ├── detect.rs       — Frida, root, jailbreak, debugger detection
│   ├── integrity.rs    — Self-integrity check (abort on tamper)
│   └── error.rs        — Thread-local error storage
├── examples/
│   ├── keygen.rs               — Generate Ed25519 keypair
│   ├── sign_config.rs          — Sign config.json
│   ├── verify_test.rs          — Verification smoke test
│   ├── flutter/guard_service.dart
│   ├── android_java/GuardLib.kt
│   ├── ios/GuardLib.swift
│   ├── python/guardlib_python.py
│   └── node/guardlib_node.js
├── scripts/
│   ├── build_all.sh                — Build for all platforms
│   ├── setup_android_linkers.sh    — Configure Android NDK linkers
│   ├── get_fingerprint.py          — Extract certificate fingerprint
│   └── compute_integrity_hash.sh  — Compute self-integrity hash
├── docs/
│   ├── ANDROID_INTEGRATION.md
│   ├── IOS_INTEGRATION.md
│   ├── FLUTTER_INTEGRATION.md
│   ├── SERVER_INTEGRATION.md
│   └── INTEGRITY_SETUP.md
├── guardlib.h          — C header (include in any C/C++/Swift/JNI project)
├── Cargo.toml
└── README.md
```

---

## License

Open Source
