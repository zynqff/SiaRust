/*
 * sign_config — Sign a config.json file with your Ed25519 private key.
 *
 * Usage:
 *   cargo run --example sign_config -- <private_key_base64> <config.json>
 *
 * Output:
 *   - config.sig (raw 64-byte signature, base64-encoded file)
 *
 * The config.json should contain at minimum:
 *   {
 *     "api_url": "https://your-backend.com",
 *     "api_fingerprint": "AA:BB:CC:..."
 *   }
 */

use std::env;
use std::fs;
use ed25519_dalek::{SigningKey, Signer};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: cargo run --example sign_config -- <private_key_base64> <config.json>");
        std::process::exit(1);
    }

    let private_key_b64 = &args[1];
    let config_path = &args[2];

    // Decode private key
    let key_bytes = match BASE64.decode(private_key_b64) {
        Ok(b) => b,
        Err(e) => { eprintln!("Invalid base64 private key: {}", e); std::process::exit(1); }
    };

    if key_bytes.len() != 32 {
        eprintln!("Private key must be 32 bytes (got {})", key_bytes.len());
        std::process::exit(1);
    }

    let key_arr: [u8; 32] = key_bytes.try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&key_arr);

    // Read config
    let config_json = match fs::read(config_path) {
        Ok(b) => b,
        Err(e) => { eprintln!("Cannot read {}: {}", config_path, e); std::process::exit(1); }
    };

    // Sign
    let signature = signing_key.sign(&config_json);
    let sig_b64 = BASE64.encode(signature.to_bytes());

    // Write .sig file
    let sig_path = format!("{}.sig", config_path.trim_end_matches(".json"));
    fs::write(&sig_path, &sig_b64).expect("Cannot write .sig file");

    println!("✅ Signed successfully");
    println!("   Config:    {}", config_path);
    println!("   Signature: {}", sig_path);
    println!("   Sig (b64): {}", sig_b64);
    println!();
    println!("Upload both files to your CDN/GitHub Pages.");
}
