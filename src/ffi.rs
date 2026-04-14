/*
 * FFI interface — C-compatible API exposed by GuardLib.
 *
 * All functions use C ABI (#[no_mangle] + extern "C").
 * All pointers are nullable — callers must check for NULL.
 * Memory management: strings returned by guard_last_error() and
 * guard_verify_config() MUST be freed by calling guard_free_string().
 *
 * Thread safety: guard_last_error() is thread-local. All other functions
 * are stateless and safe to call from any thread.
 */

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uchar};

use crate::crypto;
use crate::detect;
use crate::error;
use crate::integrity;

// ── Opaque handle ─────────────────────────────────────────────────────────────

/// Opaque guard handle. Returned by guard_init(), passed to other functions.
/// The application must NOT store or modify the contents.
#[repr(C)]
pub struct GuardHandle {
    _initialized: bool,
}

// ── guard_init ────────────────────────────────────────────────────────────────

/// Initialize GuardLib.
///
/// Performs:
///   1. Self-integrity check (aborts process on failure — cannot be caught)
///   2. Frida detection
///   3. Root / jailbreak detection
///
/// Returns: non-NULL GuardHandle on success, NULL on detection or error.
/// On NULL: call guard_last_error() to get reason.
/// Caller must NOT free the returned handle directly — call guard_destroy().
#[no_mangle]
pub extern "C" fn guard_init() -> *mut GuardHandle {
    error::clear_last_error();

    // Step 1: Self-integrity (aborts on fail — no return value possible)
    integrity::verify_self_integrity();

    // Step 2: Threat detection
    let result = detect::run_all_checks();
    if result.detected {
        error::set_last_error(&format!("Detection failed: {}", result.reason));
        return std::ptr::null_mut();
    }

    let handle = Box::new(GuardHandle { _initialized: true });
    Box::into_raw(handle)
}

/// Destroy a GuardHandle returned by guard_init().
/// Safe to call with NULL.
#[no_mangle]
pub extern "C" fn guard_destroy(handle: *mut GuardHandle) {
    if handle.is_null() { return; }
    unsafe { drop(Box::from_raw(handle)); }
}

// ── guard_verify_config ───────────────────────────────────────────────────────

/// Verify a signed config JSON and extract api_url + api_fingerprint.
///
/// Parameters:
///   handle       — from guard_init() (must not be NULL)
///   json_ptr     — UTF-8 config JSON bytes (not NUL-terminated, use json_len)
///   json_len     — byte length of json_ptr
///   sig_ptr      — raw 64-byte Ed25519 signature (NOT base64)
///   sig_len      — must be 64
///
/// Returns: JSON string: {"api_url":"...","api_fingerprint":"..."} on success.
///          NULL on failure (bad signature, missing fields, invalid handle).
///
/// IMPORTANT: The returned string is heap-allocated. Caller MUST free it
///            by passing it to guard_free_string(). Do NOT call free() directly.
///
/// The application is responsible for saving the values to SecureStorage.
/// GuardLib does not store anything.
#[no_mangle]
pub extern "C" fn guard_verify_config(
    handle: *const GuardHandle,
    json_ptr: *const c_uchar,
    json_len: usize,
    sig_ptr: *const c_uchar,
    sig_len: usize,
) -> *mut c_char {
    error::clear_last_error();

    if handle.is_null() {
        error::set_last_error("Internal error: null handle");
        return std::ptr::null_mut();
    }

    if json_ptr.is_null() || sig_ptr.is_null() {
        error::set_last_error("Internal error: null pointer argument");
        return std::ptr::null_mut();
    }

    if sig_len != 64 {
        error::set_last_error(&format!("Signature mismatch: expected 64 bytes, got {}", sig_len));
        return std::ptr::null_mut();
    }

    let json_bytes = unsafe { std::slice::from_raw_parts(json_ptr, json_len) };
    let sig_bytes = unsafe { std::slice::from_raw_parts(sig_ptr, sig_len) };

    // Run 5 independent signature checks
    if !crypto::verify_signature_multi(json_bytes, sig_bytes) {
        error::set_last_error("Signature mismatch");
        return std::ptr::null_mut();
    }

    // Parse JSON to extract required fields
    let json_str = match std::str::from_utf8(json_bytes) {
        Ok(s) => s,
        Err(_) => {
            error::set_last_error("Internal error: config is not valid UTF-8");
            return std::ptr::null_mut();
        }
    };

    let (api_url, api_fingerprint) = match extract_config_fields(json_str) {
        Some(v) => v,
        None => {
            error::set_last_error("Signature mismatch: missing api_url or api_fingerprint");
            return std::ptr::null_mut();
        }
    };

    // Return as JSON string — app saves to SecureStorage
    let result = format!(
        "{{\"api_url\":\"{}\",\"api_fingerprint\":\"{}\"}}",
        api_url.replace('"', "\\\""),
        api_fingerprint.to_uppercase().replace('"', "\\\""),
    );

    match CString::new(result) {
        Ok(cs) => cs.into_raw(),
        Err(_) => {
            error::set_last_error("Internal error: result contains NUL byte");
            std::ptr::null_mut()
        }
    }
}

// ── guard_validate_certificate ────────────────────────────────────────────────

/// Validate an HTTPS certificate against a trusted fingerprint.
///
/// Parameters:
///   handle        — from guard_init() (must not be NULL)
///   cert_der      — raw DER bytes of the server certificate
///   cert_der_len  — byte length of cert_der
///   expected_fp   — NUL-terminated C string: uppercase hex, colon-separated
///                   e.g. "AA:BB:CC:DD:..."  (SHA-256 of SPKI)
///
/// Returns: 1 if fingerprint matches, 0 if it does not match or on error.
///
/// NOTE: A return value of 0 is NOT stored in last_error — it is a normal
/// negative result. The caller must abort the HTTPS connection on 0.
/// Returns -1 on internal error (check guard_last_error()).
#[no_mangle]
pub extern "C" fn guard_validate_certificate(
    handle: *const GuardHandle,
    cert_der: *const c_uchar,
    cert_der_len: usize,
    expected_fp: *const c_char,
) -> c_int {
    if handle.is_null() || cert_der.is_null() || expected_fp.is_null() {
        error::set_last_error("Internal error: null argument to guard_validate_certificate");
        return -1;
    }

    let cert_bytes = unsafe { std::slice::from_raw_parts(cert_der, cert_der_len) };

    let fp_str = unsafe {
        match CStr::from_ptr(expected_fp).to_str() {
            Ok(s) => s,
            Err(_) => {
                error::set_last_error("Internal error: expected_fp is not valid UTF-8");
                return -1;
            }
        }
    };

    if crypto::validate_certificate_fingerprint(cert_bytes, fp_str) { 1 } else { 0 }
}

// ── guard_last_error ──────────────────────────────────────────────────────────

/// Get the last error message (thread-local).
///
/// Returns: NUL-terminated C string describing the last error, or NULL if none.
/// IMPORTANT: Caller MUST free the returned string with guard_free_string().
#[no_mangle]
pub extern "C" fn guard_last_error() -> *mut c_char {
    match error::get_last_error() {
        Some(msg) => match CString::new(msg) {
            Ok(cs) => cs.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

// ── guard_free_string ─────────────────────────────────────────────────────────

/// Free a string returned by guard_verify_config() or guard_last_error().
/// Safe to call with NULL.
#[no_mangle]
pub extern "C" fn guard_free_string(ptr: *mut c_char) {
    if ptr.is_null() { return; }
    unsafe { drop(CString::from_raw(ptr)); }
}

// ── guard_version ─────────────────────────────────────────────────────────────

/// Returns the library version string (e.g. "1.0.0").
/// The returned pointer is a static string — do NOT free it.
#[no_mangle]
pub extern "C" fn guard_version() -> *const c_char {
    static VERSION: &[u8] = b"1.0.0\0";
    VERSION.as_ptr() as *const c_char
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Minimal JSON field extractor (no external dep).
/// Looks for "api_url" and "api_fingerprint" string values.
fn extract_config_fields(json: &str) -> Option<(String, String)> {
    let api_url = extract_json_string(json, "api_url")?;
    let api_fingerprint = extract_json_string(json, "api_fingerprint")?;
    if api_url.is_empty() || api_fingerprint.is_empty() { return None; }
    Some((api_url, api_fingerprint))
}

/// Extract a string value from a flat JSON object by key.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let search = format!("\"{}\"", key);
    let key_pos = json.find(&search)?;
    let after_key = &json[key_pos + search.len()..];
    let colon_pos = after_key.find(':')? ;
    let after_colon = after_key[colon_pos + 1..].trim_start();
    if !after_colon.starts_with('"') { return None; }
    let inner = &after_colon[1..];
    let end = inner.find('"')?;
    Some(inner[..end].to_string())
}
