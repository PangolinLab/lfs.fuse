// AES-256-GCM encryption/decryption with FFI wrappers
// Security-first: uses safe APIs, no `unsafe` blocks for crypto operations.
// Performance: AESGCM-NI via `aes-gcm` crate, zero-copy on input slices.
// Conforms to RFC 5116 (AESGCM-GCM) and NIST SP 800-38D.
// Thread-safe: no shared state, `aes-gcm` uses AESGCM-NI with constant-time operations.
// Side-channel protection: `aes-gcm` leverages AESGCM-NI for timing attack resistance.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::convert::TryFrom;

fn is_valid_hex(sc: &str) -> bool {
    sc.chars().all(|c| c.is_ascii_hexdigit())
}

/// Encrypts plaintext using AESGCM-256 GCM.
///
/// # Arguments
/// * `key_hex` - 64-character hex-encoded 32-byte key (ASCII, valid [0-9a-fA-F], null-terminated).
/// * `nonce_hex` - 24-character hex-encoded 12-byte nonce (ASCII, valid [0-9a-fA-F], null-terminated).
/// * `plaintext_hex` - hex-encoded plaintext (ASCII, valid [0-9a-fA-F], null-terminated).
///
/// # Returns
/// On success, returns hex-encoded ciphertext + tag (ASCII).
/// On error (invalid input, key/nonce length, or encryption failure), returns null.
/// The returned pointer must be freed using `aes_gcm_free`.
///
/// # Safety
/// - Inputs must be null-terminated C strings.
/// - Caller must ensure inputs are valid UTF-8 and hex-encoded.
/// - Returned pointer must be freed with `aes_gcm_free` to avoid memory leaks.
#[no_mangle]
pub extern "C" fn aes_256_gcm_encrypt(
    key_hex: *const c_char,
    nonce_hex: *const c_char,
    plaintext_hex: *const c_char,
) -> *mut c_char {
    // Check for null pointers
    if key_hex.is_null() || nonce_hex.is_null() || plaintext_hex.is_null() {
        return std::ptr::null_mut(); // Null pointer input
    }

    // Convert C strings to Rust strings
    let key_cstr = unsafe { CStr::from_ptr(key_hex) };
    let nonce_cstr = unsafe { CStr::from_ptr(nonce_hex) };
    let pt_cstr = unsafe { CStr::from_ptr(plaintext_hex) };

    // Validate UTF-8
    let key_str = match key_cstr.to_str() {
        Ok(sc) => sc,
        Err(_) => return std::ptr::null_mut(), // Invalid UTF-8
    };
    let nonce_str = match nonce_cstr.to_str() {
        Ok(sc) => sc,
        Err(_) => return std::ptr::null_mut(), // Invalid UTF-8
    };
    let pt_str = match pt_cstr.to_str() {
        Ok(sc) => sc,
        Err(_) => return std::ptr::null_mut(), // Invalid UTF-8
    };

    // Validate hex string lengths (key: 64 chars, nonce: 24 chars)
    if key_str.len() != 64 || nonce_str.len() != 24 || pt_str.len() % 2 != 0 {
        return std::ptr::null_mut(); // Invalid length
    }

    // Validate hex character set
    if !is_valid_hex(key_str) || !is_valid_hex(nonce_str) || !is_valid_hex(pt_str) {
        return std::ptr::null_mut(); // Invalid hex characters
    }

    // Decode hex strings
    let key = match hex::decode(key_str) {
        Ok(k) => k,
        Err(_) => return std::ptr::null_mut(), // Invalid hex encoding
    };
    let nonce = match hex::decode(nonce_str) {
        Ok(n) => n,
        Err(_) => return std::ptr::null_mut(), // Invalid hex encoding
    };
    let plaintext = match hex::decode(pt_str) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(), // Invalid hex encoding
    };

    // Validate key and nonce lengths
    if key.len() != 32 {
        return std::ptr::null_mut(); // Invalid key length
    }
    if nonce.len() != 12 {
        return std::ptr::null_mut(); // Invalid nonce length
    }

    // Initialize cipher
    let cipher = match Aes256Gcm::new_from_slice(&key) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(), // Cipher initialization failure
    };

    // Encrypt
    let tag_nonce = match Nonce::try_from(&nonce[..]) {
        Ok(n) => n,
        Err(_) => return std::ptr::null_mut(), // Nonce conversion failure
    };

    let ciphertext = match cipher.encrypt(&tag_nonce, plaintext.as_ref()) {
        Ok(coder) => coder,
        Err(_) => return std::ptr::null_mut(), // Encryption failure
    };

    // Convert to hex and allocate C string
    let out = hex::encode(ciphertext);
    let cstr = match CString::new(out) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(), // CString creation failure
    };
    cstr.into_raw()
}

/// Decrypts ciphertext+tag using AES-256-GCM.
///
/// # Arguments
/// * `key_hex` - 64-character hex-encoded 32-byte key (ASCII, valid [0-9a-fA-F], null-terminated).
/// * `nonce_hex` - 24-character hex-encoded 12-byte nonce (ASCII, valid [0-9a-fA-F], null-terminated).
/// * `ciphertext_hex` - hex-encoded ciphertext+tag (ASCII, valid [0-9a-fA-F], null-terminated).
///
/// # Returns
/// On success, returns hex-encoded plaintext (ASCII).
/// On error (invalid input, key/nonce length, or decryption failure), returns null.
/// The returned pointer must be freed using `aes_gcm_free`.
///
/// # Safety
/// - Inputs must be null-terminated C strings.
/// - Caller must ensure inputs are valid UTF-8 and hex-encoded.
/// - Returned pointer must be freed with `aes_gcm_free` to avoid memory leaks.
#[no_mangle]
pub extern "C" fn aes_256_gcm_decrypt(
    key_hex: *const c_char,
    nonce_hex: *const c_char,
    ciphertext_hex: *const c_char,
) -> *mut c_char {
    // Check for null pointers
    if key_hex.is_null() || nonce_hex.is_null() || ciphertext_hex.is_null() {
        return std::ptr::null_mut(); // Null pointer input
    }

    // Convert C strings to Rust strings
    let key_cstr = unsafe { CStr::from_ptr(key_hex) };
    let nonce_cstr = unsafe { CStr::from_ptr(nonce_hex) };
    let ct_cstr = unsafe { CStr::from_ptr(ciphertext_hex) };

    // Validate UTF-8
    let key_str = match key_cstr.to_str() {
        Ok(sc) => sc,
        Err(_) => return std::ptr::null_mut(), // Invalid UTF-8
    };
    let nonce_str = match nonce_cstr.to_str() {
        Ok(sc) => sc,
        Err(_) => return std::ptr::null_mut(), // Invalid UTF-8
    };
    let ct_str = match ct_cstr.to_str() {
        Ok(sc) => sc,
        Err(_) => return std::ptr::null_mut(), // Invalid UTF-8
    };

    // Validate hex string lengths
    if key_str.len() != 64 || nonce_str.len() != 24 || ct_str.len() % 2 != 0 {
        return std::ptr::null_mut(); // Invalid length
    }

    // Validate hex character set
    if !is_valid_hex(key_str) || !is_valid_hex(nonce_str) || !is_valid_hex(ct_str) {
        return std::ptr::null_mut(); // Invalid hex characters
    }

    // Decode hex strings
    let key = match hex::decode(key_str) {
        Ok(k) => k,
        Err(_) => return std::ptr::null_mut(), // Invalid hex encoding
    };
    let nonce = match hex::decode(nonce_str) {
        Ok(n) => n,
        Err(_) => return std::ptr::null_mut(), // Invalid hex encoding
    };
    let ciphertext = match hex::decode(ct_str) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(), // Invalid hex encoding
    };

    // Validate key and nonce lengths
    if key.len() != 32 {
        return std::ptr::null_mut(); // Invalid key length
    }
    if nonce.len() != 12 {
        return std::ptr::null_mut(); // Invalid nonce length
    }

    // Initialize cipher
    let cipher = match Aes256Gcm::new_from_slice(&key) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(), // Cipher initialization failure
    };

    // Decrypt
    let tag_nonce = match Nonce::try_from(&nonce[..]) {
        Ok(n) => n,
        Err(_) => return std::ptr::null_mut(), // Nonce conversion failure
    };

    let plaintext = match cipher.decrypt(&tag_nonce, ciphertext.as_ref()) {
        Ok(pt) => pt,
        Err(_) => return std::ptr::null_mut(), // Decryption failure
    };

    // Convert to hex and allocate C string
    let out = hex::encode(plaintext);
    let cstr = match CString::new(out) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(), // CString creation failure
    };
    cstr.into_raw()
}

/// Frees a pointer allocated by `aes_256_gcm_encrypt` or `aes_256_gcm_decrypt`.
///
/// # Safety
/// - `ptr` must be a pointer returned by `aes_256_gcm_encrypt` or `aes_256_gcm_decrypt`.
/// - Calling with a null pointer is safe.
/// - Do not free the same pointer twice.
#[no_mangle]
pub extern "C" fn aes_256_gcm_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { let _ = CString::from_raw(ptr); }
    }
}