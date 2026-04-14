/*
 * GuardLib — Cryptographic Config Verification & Certificate Pinning
 * Rust FFI Library — Cross-platform (Android, iOS, Linux, Windows, macOS)
 *
 * Architecture:
 *   - Rust returns OK / NOT OK. The application makes decisions.
 *   - Only exception: tamper detection triggers process::abort().
 *   - All crypto runs inside Rust. Never exposed to Frida hooks.
 */

/*#![forbid(unsafe_code)]*/
#![deny(clippy::all)]

mod crypto;
mod detect;
mod error;
mod integrity;
mod ffi;

pub use ffi::*;
