# Self-Integrity Setup

GuardLib can verify that its own code has not been patched at runtime. This is Scenario 5 from the security spec: if the code region is modified, `guard_init()` calls `std::process::abort()`.

---

## How it works

At `guard_init()`, GuardLib reads a region of its own `.text` segment in memory, computes SHA-256, and compares it to `EXPECTED_HASH` baked into the binary. If they differ, the process aborts.

---

## Setup workflow

This must be done **after** your final release build. The hash changes with every recompile.

### Step 1 — Build release

```bash
./scripts/build_all.sh android  # or ios, linux, etc.
```

### Step 2 — Compute hash

```bash
./scripts/compute_integrity_hash.sh dist/android/jniLibs/arm64-v8a/libguardlib.so
```

Output:
```
Computing integrity hash for: dist/android/jniLibs/arm64-v8a/libguardlib.so
Function offset: 0x12a40
Region size: 4096 bytes

SHA-256: [0x4a, 0x2f, 0x11, 0x88, ...]

Paste into src/integrity.rs:
static EXPECTED_HASH: [u8; 32] = [
    0x4a, 0x2f, 0x11, 0x88, 0x99, 0xAB, 0xCD, 0xEF,
    ...
];
```

### Step 3 — Embed hash

Open `src/integrity.rs`. Replace:
```rust
static EXPECTED_HASH: [u8; 32] = [0u8; 32]; // REPLACE AFTER BUILD
const INTEGRITY_CHECK_DISABLED: bool = true;
```

With:
```rust
static EXPECTED_HASH: [u8; 32] = [
    0x4a, 0x2f, 0x11, 0x88, /* ... */
];
const INTEGRITY_CHECK_DISABLED: bool = false;
```

### Step 4 — Rebuild

```bash
./scripts/build_all.sh android
```

### Step 5 — Verify

```bash
./scripts/compute_integrity_hash.sh dist/android/jniLibs/arm64-v8a/libguardlib.so
```

The hash should match what you embedded. ✅

---

## Important: separate hash per target

Each compiled binary has a different hash. You need to:

- Compute and embed hash for `aarch64-linux-android`
- Compute and embed hash for `armv7-linux-androideabi`
- Compute and embed hash for iOS device
- etc.

This means integrity.rs needs **per-target hashes**:

```rust
#[cfg(target_arch = "aarch64")]
#[cfg(target_os = "android")]
static EXPECTED_HASH: [u8; 32] = [ /* arm64-v8a hash */ ];

#[cfg(target_arch = "arm")]
#[cfg(target_os = "android")]
static EXPECTED_HASH: [u8; 32] = [ /* armeabi-v7a hash */ ];
```

The `compute_integrity_hash.sh` script outputs the correct `#[cfg(...)]` block for you.

---

## Development workflow

During development, keep `INTEGRITY_CHECK_DISABLED = true`. Only enable it for your final release build intended for distribution.

If you accidentally enable it with a wrong hash, the app will crash immediately on every launch. To fix: rebuild with `INTEGRITY_CHECK_DISABLED = true`.

---

## Limitations

- The hash covers a 4KB region around the `verify_self_integrity` function. This does not cover the entire library — only the critical region.
- An attacker who patches a different part of the binary (outside this region) would not trigger this check.
- This is one layer of defense, not a complete anti-tamper solution. Combine with: code obfuscation, multiple signature checks, server-side anomaly detection.
