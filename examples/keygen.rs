/*
 * keygen — Generate an Ed25519 keypair for GuardLib.
 *
 * Usage: cargo run --example keygen
 *
 * Output:
 *   - Private key (base64) — keep SECRET, use to sign config.json
 *   - Public key (base64)  — embed in GuardLib source (crypto.rs)
 *   - Key parts + masks    — ready to paste into crypto.rs
 */

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

fn main() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let private_b64 = BASE64.encode(signing_key.to_bytes());
    let public_bytes = verifying_key.to_bytes();
    let public_b64 = BASE64.encode(&public_bytes);

    println!("═══════════════════════════════════════════════════════");
    println!("  GuardLib Key Generation");
    println!("═══════════════════════════════════════════════════════");
    println!();
    println!("🔐 PRIVATE KEY (base64) — KEEP SECRET:");
    println!("   {}", private_b64);
    println!();
    println!("🔑 PUBLIC KEY (base64) — embed in GuardLib:");
    println!("   {}", public_b64);
    println!();
    println!("📦 Raw public key bytes (32):");
    let hex: Vec<String> = public_bytes.iter().map(|b| format!("0x{:02x}", b)).collect();
    println!("   [{}]", hex.join(", "));
    println!();

    // Generate split + masked parts
    println!("─── Obfuscated key parts for crypto.rs ───────────────");
    println!();

    let masks: [(&str, Vec<u8>, usize, usize); 5] = [
        ("A", vec![0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0x42], 0,  7),
        ("B", vec![0xCA, 0xFE, 0xBA, 0xBE, 0x55, 0xAA, 0x11], 7,  7),
        ("C", vec![0xFE, 0xED, 0xFA, 0xCE, 0x77, 0x88, 0x00], 14, 6),
        ("D", vec![0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x00], 20, 6),
        ("E", vec![0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x00], 26, 6),
    ];

    for (name, mask, start, len) in &masks {
        let actual_mask: Vec<u8> = mask[..*len].to_vec();
        let part: Vec<u8> = public_bytes[*start..*start + *len]
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ actual_mask[i % actual_mask.len()])
            .collect();

        let mask_fmt: Vec<String> = actual_mask.iter().map(|b| format!("0x{:02X}", b)).collect();
        let part_fmt: Vec<String> = part.iter().map(|b| format!("0x{:02X}", b)).collect();

        println!("const MASK_{}: [u8; {}] = [{}];", name, len, mask_fmt.join(", "));
        println!("const KEY_PART_{}: [u8; {}] = [{}];", name, len, part_fmt.join(", "));
        println!();
    }

    println!("═══════════════════════════════════════════════════════");
    println!("  Copy the MASK_* and KEY_PART_* lines into src/crypto.rs");
    println!("  Keep the private key in a secure location (e.g. GitHub Secrets)");
    println!("═══════════════════════════════════════════════════════");
}
