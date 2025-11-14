use aes_gcm_siv::aead::{Aead, KeyInit, Nonce};
use aes_gcm_siv::{Aes256GcmSiv};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

fn is_valid_hex(sc: &str) -> bool {
    sc.chars().all(|c| c.is_ascii_hexdigit())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_256_gcm_siv_encrypt(
    key_hex: *const c_char,
    nonce_hex: *const c_char,
    plaintext_hex: *const c_char,
) -> *mut c_char {
    if key_hex.is_null() || nonce_hex.is_null() || plaintext_hex.is_null() {
        return std::ptr::null_mut();
    }
    let key_cstr = unsafe { CStr::from_ptr(key_hex) };
    let nonce_cstr = unsafe { CStr::from_ptr(nonce_hex) };
    let pt_cstr = unsafe { CStr::from_ptr(plaintext_hex) };

    let key_str: &str = match key_cstr.to_str() { Ok(sc) => sc, Err(_) => return std::ptr::null_mut() };
    let nonce_str: &str = match nonce_cstr.to_str() { Ok(sc) => sc, Err(_) => return std::ptr::null_mut() };
    let pt_str: &str = match pt_cstr.to_str() { Ok(sc) => sc, Err(_) => return std::ptr::null_mut() };

    if key_str.len() != 64 || nonce_str.len() != 24 || pt_str.len() % 2 != 0 {
        return std::ptr::null_mut();
    }
    if !is_valid_hex(key_str) || !is_valid_hex(nonce_str) || !is_valid_hex(pt_str) {
        return std::ptr::null_mut();
    }

    let key: Vec<u8> = match hex::decode(key_str) { Ok(k) => k, Err(_) => return std::ptr::null_mut() };
    let nonce: Vec<u8> = match hex::decode(nonce_str) { Ok(n) => n, Err(_) => return std::ptr::null_mut() };
    let plaintext: Vec<u8> = match hex::decode(pt_str) { Ok(b) => b, Err(_) => return std::ptr::null_mut() };

    if key.len() != 32 || nonce.len() != 12 {
        return std::ptr::null_mut();
    }

    let cipher = match Aes256GcmSiv::new_from_slice(&key) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    // 明确指定 Nonce 类型
    let nonce_arr: [u8; 12] = nonce.try_into().unwrap_or([0u8; 12]);
    let nonce_obj = Nonce::<Aes256GcmSiv>::from_slice(&nonce_arr);

    let ciphertext = match cipher.encrypt(nonce_obj, plaintext.as_ref()) {
        Ok(coder) => coder,
        Err(_) => return std::ptr::null_mut(),
    };

    let out = hex::encode(ciphertext);
    let cstr = match CString::new(out) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    cstr.into_raw()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_256_gcm_siv_decrypt(
    key_hex: *const c_char,
    nonce_hex: *const c_char,
    ciphertext_hex: *const c_char,
) -> *mut c_char {
    if key_hex.is_null() || nonce_hex.is_null() || ciphertext_hex.is_null() {
        return std::ptr::null_mut();
    }
    let key_cstr = unsafe { CStr::from_ptr(key_hex) };
    let nonce_cstr = unsafe { CStr::from_ptr(nonce_hex) };
    let ct_cstr = unsafe { CStr::from_ptr(ciphertext_hex) };

    let key_str: &str = match key_cstr.to_str() { Ok(sc) => sc, Err(_) => return std::ptr::null_mut() };
    let nonce_str: &str = match nonce_cstr.to_str() { Ok(sc) => sc, Err(_) => return std::ptr::null_mut() };
    let ct_str: &str = match ct_cstr.to_str() { Ok(sc) => sc, Err(_) => return std::ptr::null_mut() };

    if key_str.len() != 64 || nonce_str.len() != 24 || ct_str.len() % 2 != 0 {
        return std::ptr::null_mut();
    }
    if !is_valid_hex(key_str) || !is_valid_hex(nonce_str) || !is_valid_hex(ct_str) {
        return std::ptr::null_mut();
    }

    let key: Vec<u8> = match hex::decode(key_str) { Ok(k) => k, Err(_) => return std::ptr::null_mut() };
    let nonce: Vec<u8> = match hex::decode(nonce_str) { Ok(n) => n, Err(_) => return std::ptr::null_mut() };
    let ciphertext: Vec<u8> = match hex::decode(ct_str) { Ok(c) => c, Err(_) => return std::ptr::null_mut() };

    if key.len() != 32 || nonce.len() != 12 {
        return std::ptr::null_mut();
    }

    let cipher = match Aes256GcmSiv::new_from_slice(&key) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    // 明确指定 Nonce 类型
    let nonce_arr: [u8; 12] = nonce.try_into().unwrap_or([0u8; 12]);
    let nonce_obj = Nonce::<Aes256GcmSiv>::from_slice(&nonce_arr);

    let plaintext = match cipher.decrypt(nonce_obj, ciphertext.as_ref()) {
        Ok(pt) => pt,
        Err(_) => return std::ptr::null_mut(),
    };

    let out = hex::encode(plaintext);
    let cstr = match CString::new(out) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    cstr.into_raw()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_256_gcm_siv_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { let _ = CString::from_raw(ptr); }
    }
}
