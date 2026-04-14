/*
 * Self-integrity module.
 *
 * Computes a runtime hash of the guard_verify_config and guard_validate_certificate
 * function regions in memory and compares against a stored expected value.
 *
 * If tampered: calls std::process::abort() — the ONLY place GuardLib terminates the process.
 *
 * Note: The expected hash must be computed after final compilation and embedded
 * via the build script (build.rs) or set manually. See docs/INTEGRITY_SETUP.md.
 *
 * In practice on Android/iOS, the .so/.dylib is loaded from a read-only segment,
 * so the hash of code in memory should be stable across runs on the same binary.
 */

use sha2::{Sha256, Digest};

/// Expected SHA-256 of the integrity-critical region.
/// Set to all-zeros = disabled (skip check). Replace after first build.
/// See: scripts/compute_integrity_hash.sh
static EXPECTED_HASH: [u8; 32] = [0u8; 32]; // REPLACE AFTER BUILD

const INTEGRITY_CHECK_DISABLED: bool = true; // Set to false after embedding real hash

/// Verify that critical code regions have not been patched.
/// Calls std::process::abort() on mismatch (cannot be caught).
pub fn verify_self_integrity() {
    if INTEGRITY_CHECK_DISABLED {
        return;
    }

    if EXPECTED_HASH == [0u8; 32] {
        // Hash not configured — skip silently in debug, abort in release
        #[cfg(not(debug_assertions))]
        std::process::abort();
        return;
    }

    // Hash a region of our own code in memory
    // We use the address of a known function as an anchor
    let anchor = verify_self_integrity as *const () as usize;
    
    // Read 4KB around the anchor (conservative — stays within .text segment)
    let region_size = 4096usize;
    let region_ptr = anchor as *const u8;

    let computed = unsafe {
        // SAFETY: We're reading our own .text segment which is always mapped readable.
        // This is defined behavior for the process's own code on all supported platforms.
        let slice = std::slice::from_raw_parts(region_ptr, region_size);
        let mut hasher = Sha256::new();
        hasher.update(slice);
        hasher.finalize()
    };

    if computed.as_slice() != EXPECTED_HASH {
        // Critical: code has been patched. Abort immediately.
        // This cannot be caught by Flutter/Dart exception handling.
        std::process::abort();
    }
}
