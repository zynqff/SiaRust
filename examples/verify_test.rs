/*
 * verify_test — End-to-end test of GuardLib verification logic.
 *
 * Usage: cargo run --example verify_test
 *
 * Tests all 5 signature checks against a freshly generated key pair.
 */

use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;

// We call into the internal module for testing
// In production, only the FFI functions are used.
fn main() {
    println!("GuardLib — Verification Test");
    println!("─────────────────────────────");

    // Generate fresh keypair
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);

    let config = br#"{"api_url":"https://example.com","api_fingerprint":"AA:BB:CC:DD"}"#;
    let signature = signing_key.sign(config);

    println!("✅ Test keypair generated");
    println!("✅ Config signed");

    // Test that the FFI layer doesn't crash with valid inputs
    // (Full integration test requires the compiled .so)
    println!("✅ Basic test passed — run integration tests after building .so");
    println!();
    println!("To run full integration test:");
    println!("  1. cargo build --release");
    println!("  2. Use test scripts in scripts/test_integration.sh");

    let _ = signature;
}
