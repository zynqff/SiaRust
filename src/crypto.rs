/*
 * Cryptographic verification module.
 *
 * Key is split into 5 parts, each XOR-obfuscated with a unique mask.
 * Signature is verified 5 independent times using 5 separate code paths.
 * All checks must pass — short-circuit evaluation is intentionally avoided.
 *
 * To configure: replace KEY_PART_* and MASK_* constants with your own values.
 * Run: cargo run --example keygen -- <your_public_key_base64>
 */

use ed25519_dalek::{Signature, VerifyingKey, Verifier};

// ── Key parts (raw 32-byte Ed25519 public key, split + XOR-masked) ──────────
// Each part: XOR with its MASK before use.
// Parts concatenated in order A‥E reconstruct the 32-byte key.

// Example key from pinning_service.dart (MCowBQYDK2VwAyEAixC+QsgLKtfAUHCrpTqqlmxChRjQpe5MMPdzHtZves8=)
// Raw 32 bytes extracted from PKIX DER (skip first 12 bytes of DER header):
// 8b 10 be 42 c8 0b 2a d7 c0 50 70 ab a5 3a aa 96
// 6c 42 85 18 d0 a5 ee 4c 30 f7 73 1e d6 7b de cf

const MASK_A: [u8; 7] = [0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0x42];
const MASK_B: [u8; 7] = [0xCA, 0xFE, 0xBA, 0xBE, 0x55, 0xAA, 0x11];
const MASK_C: [u8; 6] = [0xFE, 0xED, 0xFA, 0xCE, 0x77, 0x88];
const MASK_D: [u8; 6] = [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45];
const MASK_E: [u8; 6] = [0x99, 0x88, 0x77, 0x66, 0x55, 0x44];

// KEY_PART_X[i] = real_byte[i] ^ MASK_X[i % MASK_X.len()]
const KEY_PART_A: [u8; 7] = [
    0x8b ^ 0xDE, 0x10 ^ 0xAD, 0xbe ^ 0xBE, 0x42 ^ 0xEF,
    0xc8 ^ 0x13, 0x0b ^ 0x37, 0x2a ^ 0x42,
];
const KEY_PART_B: [u8; 7] = [
    0xd7 ^ 0xCA, 0xc0 ^ 0xFE, 0x50 ^ 0xBA, 0x70 ^ 0xBE,
    0xab ^ 0x55, 0xa5 ^ 0xAA, 0x3a ^ 0x11,
];
const KEY_PART_C: [u8; 6] = [
    0xaa ^ 0xFE, 0x96 ^ 0xED, 0x6c ^ 0xFA, 0x42 ^ 0xCE,
    0x85 ^ 0x77, 0x18 ^ 0x88,
];
const KEY_PART_D: [u8; 6] = [
    0xd0 ^ 0xAB, 0xa5 ^ 0xCD, 0xee ^ 0xEF, 0x4c ^ 0x01,
    0x30 ^ 0x23, 0xf7 ^ 0x45,
];
const KEY_PART_E: [u8; 6] = [
    0x73 ^ 0x99, 0x1e ^ 0x88, 0xd6 ^ 0x77, 0x7b ^ 0x66,
    0xde ^ 0x55, 0xcf ^ 0x44,
];

/// Reconstruct the 32-byte public key from obfuscated parts.
/// Called 5 times from different code locations — compiler cannot deduplicate easily.
#[inline(never)]
fn reconstruct_key_v1() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (i, &b) in KEY_PART_A.iter().enumerate() { key[i] = b ^ MASK_A[i % MASK_A.len()]; }
    for (i, &b) in KEY_PART_B.iter().enumerate() { key[7 + i] = b ^ MASK_B[i % MASK_B.len()]; }
    for (i, &b) in KEY_PART_C.iter().enumerate() { key[14 + i] = b ^ MASK_C[i % MASK_C.len()]; }
    for (i, &b) in KEY_PART_D.iter().enumerate() { key[20 + i] = b ^ MASK_D[i % MASK_D.len()]; }
    for (i, &b) in KEY_PART_E.iter().enumerate() { key[26 + i] = b ^ MASK_E[i % MASK_E.len()]; }
    key
}

#[inline(never)]
fn reconstruct_key_v2() -> [u8; 32] {
    // Reconstruction in reverse order — different binary pattern
    let mut key = [0u8; 32];
    for (i, &b) in KEY_PART_E.iter().enumerate() { key[26 + i] = b ^ MASK_E[i % MASK_E.len()]; }
    for (i, &b) in KEY_PART_D.iter().enumerate() { key[20 + i] = b ^ MASK_D[i % MASK_D.len()]; }
    for (i, &b) in KEY_PART_C.iter().enumerate() { key[14 + i] = b ^ MASK_C[i % MASK_C.len()]; }
    for (i, &b) in KEY_PART_B.iter().enumerate() { key[7 + i] = b ^ MASK_B[i % MASK_B.len()]; }
    for (i, &b) in KEY_PART_A.iter().enumerate() { key[i] = b ^ MASK_A[i % MASK_A.len()]; }
    key
}

#[inline(never)]
fn reconstruct_key_v3() -> [u8; 32] {
    // Byte-by-byte with inline XOR — different IR pattern
    [
        KEY_PART_A[0] ^ MASK_A[0], KEY_PART_A[1] ^ MASK_A[1], KEY_PART_A[2] ^ MASK_A[2],
        KEY_PART_A[3] ^ MASK_A[3], KEY_PART_A[4] ^ MASK_A[4], KEY_PART_A[5] ^ MASK_A[5],
        KEY_PART_A[6] ^ MASK_A[6],
        KEY_PART_B[0] ^ MASK_B[0], KEY_PART_B[1] ^ MASK_B[1], KEY_PART_B[2] ^ MASK_B[2],
        KEY_PART_B[3] ^ MASK_B[3], KEY_PART_B[4] ^ MASK_B[4], KEY_PART_B[5] ^ MASK_B[5],
        KEY_PART_B[6] ^ MASK_B[6],
        KEY_PART_C[0] ^ MASK_C[0], KEY_PART_C[1] ^ MASK_C[1], KEY_PART_C[2] ^ MASK_C[2],
        KEY_PART_C[3] ^ MASK_C[3], KEY_PART_C[4] ^ MASK_C[4], KEY_PART_C[5] ^ MASK_C[5],
        KEY_PART_D[0] ^ MASK_D[0], KEY_PART_D[1] ^ MASK_D[1], KEY_PART_D[2] ^ MASK_D[2],
        KEY_PART_D[3] ^ MASK_D[3], KEY_PART_D[4] ^ MASK_D[4], KEY_PART_D[5] ^ MASK_D[5],
        KEY_PART_E[0] ^ MASK_E[0], KEY_PART_E[1] ^ MASK_E[1], KEY_PART_E[2] ^ MASK_E[2],
        KEY_PART_E[3] ^ MASK_E[3], KEY_PART_E[4] ^ MASK_E[4], KEY_PART_E[5] ^ MASK_E[5],
    ]
}

#[inline(never)]
fn reconstruct_key_v4() -> [u8; 32] {
    // Stack-allocated with pointer arithmetic style
    let parts: [(&[u8], &[u8], usize); 5] = [
        (&KEY_PART_A, &MASK_A, 0),
        (&KEY_PART_B, &MASK_B, 7),
        (&KEY_PART_C, &MASK_C, 14),
        (&KEY_PART_D, &MASK_D, 20),
        (&KEY_PART_E, &MASK_E, 26),
    ];
    let mut key = [0u8; 32];
    for (part, mask, offset) in parts {
        for (i, &b) in part.iter().enumerate() {
            key[offset + i] = b ^ mask[i % mask.len()];
        }
    }
    key
}

#[inline(never)]
fn reconstruct_key_v5() -> [u8; 32] {
    // Functional-style fold — unique IR
    let mut key = [0u8; 32];
    [
        (KEY_PART_A.as_slice(), MASK_A.as_slice(), 0usize),
        (KEY_PART_B.as_slice(), MASK_B.as_slice(), 7),
        (KEY_PART_C.as_slice(), MASK_C.as_slice(), 14),
        (KEY_PART_D.as_slice(), MASK_D.as_slice(), 20),
        (KEY_PART_E.as_slice(), MASK_E.as_slice(), 26),
    ]
    .iter()
    .for_each(|(part, mask, offset)| {
        part.iter().enumerate().for_each(|(i, &b)| {
            key[offset + i] = b ^ mask[i % mask.len()];
        });
    });
    key
}

/// Internal single verify using a given key.
#[inline(never)]
fn verify_once(msg: &[u8], sig_bytes: &[u8], key_bytes: [u8; 32]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(&key_bytes) else { return false; };
    if sig_bytes.len() != 64 { return false; }
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(msg, &sig).is_ok()
}

/// Verify Ed25519 signature using 5 independent checks.
/// All 5 must pass. Uses `&` (bitwise AND) to prevent short-circuit.
pub fn verify_signature_multi(message: &[u8], signature: &[u8]) -> bool {
    let r1 = verify_once(message, signature, reconstruct_key_v1());
    let r2 = verify_once(message, signature, reconstruct_key_v2());
    let r3 = verify_once(message, signature, reconstruct_key_v3());
    let r4 = verify_once(message, signature, reconstruct_key_v4());
    let r5 = verify_once(message, signature, reconstruct_key_v5());

    // All 5 must be true. Bitwise & ensures no short-circuit — all execute.
    r1 & r2 & r3 & r4 & r5
}

/// Compute SPKI SHA-256 fingerprint from raw DER certificate bytes.
/// Returns hex string (uppercase, colon-separated) or None on parse error.
pub fn spki_sha256_hex(cert_der: &[u8]) -> Option<String> {
    let spki = extract_spki(cert_der)?;
    let hash = sha256(&spki);
    let hex: Vec<String> = hash.iter().map(|b| format!("{:02X}", b)).collect();
    Some(hex.join(":"))
}

/// Validate certificate fingerprint.
/// expected_fp: uppercase hex, colon-separated (e.g. "AA:BB:CC:...")
pub fn validate_certificate_fingerprint(cert_der: &[u8], expected_fp: &str) -> bool {
    let Some(actual) = spki_sha256_hex(cert_der) else { return false; };
    // Constant-time comparison to prevent timing attacks
    constant_time_eq(actual.as_bytes(), expected_fp.to_uppercase().as_bytes())
}

/// Constant-time byte slice comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// SHA-256 using tiny pure-Rust implementation (no OpenSSL dependency).
fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Extract SPKI (SubjectPublicKeyInfo) from X.509 DER certificate.
/// Returns the raw SPKI bytes for hashing.
fn extract_spki(der: &[u8]) -> Option<&[u8]> {
    // X.509 structure:
    // SEQUENCE {                    <- Certificate
    //   SEQUENCE {                  <- TBSCertificate
    //     [0] version (optional)
    //     INTEGER serialNumber
    //     SEQUENCE signatureAlgorithm
    //     SEQUENCE issuer
    //     SEQUENCE validity
    //     SEQUENCE subject
    //     SEQUENCE subjectPublicKeyInfo  <- we want this
    //   }
    //   ...
    // }

    let mut pos = 0usize;

    // Enter outer Certificate SEQUENCE
    pos = enter_sequence(der, pos)?;
    // Enter TBSCertificate SEQUENCE
    pos = enter_sequence(der, pos)?;

    // Skip optional [0] version
    if pos < der.len() && der[pos] == 0xa0 {
        let (_, skip) = read_length(der, pos + 1)?;
        pos = pos + 1 + skip;
    }

    // Skip: serialNumber, signatureAlgorithm, issuer, validity, subject (5 elements)
    for _ in 0..5 {
        pos = skip_element(der, pos)?;
    }

    // Now pos points to subjectPublicKeyInfo SEQUENCE
    let spki_start = pos;
    let (_, total_len) = element_total_length(der, pos)?;
    let spki_end = spki_start + total_len;

    if spki_end > der.len() { return None; }
    Some(&der[spki_start..spki_end])
}

fn enter_sequence(der: &[u8], pos: usize) -> Option<usize> {
    if pos >= der.len() || der[pos] != 0x30 { return None; }
    let (content_start, _) = read_length(der, pos + 1)?;
    Some(content_start)
}

fn skip_element(der: &[u8], pos: usize) -> Option<usize> {
    let (_, total) = element_total_length(der, pos)?;
    Some(pos + total)
}

fn element_total_length(der: &[u8], pos: usize) -> Option<(usize, usize)> {
    if pos + 1 >= der.len() { return None; }
    let (content_start, content_len) = read_length(der, pos + 1)?;
    let total = (content_start - pos) + content_len;
    Some((content_start, total))
}

/// Returns (position_after_length, content_length)
fn read_length(der: &[u8], pos: usize) -> Option<(usize, usize)> {
    if pos >= der.len() { return None; }
    let first = der[pos];
    if first & 0x80 == 0 {
        Some((pos + 1, first as usize))
    } else {
        let num_bytes = (first & 0x7f) as usize;
        if num_bytes == 0 || pos + 1 + num_bytes > der.len() { return None; }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | (der[pos + 1 + i] as usize);
        }
        Some((pos + 1 + num_bytes, len))
    }
}
