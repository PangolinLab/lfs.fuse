// lib.rs
use std::os::raw::{c_uchar, c_int};
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce, KeyInit};
use chacha20poly1305::aead::{Aead};
use std::slice;

#[unsafe(no_mangle)]
pub extern "C" fn xchacha20_encrypt(
    key_ptr: *const c_uchar,
    nonce_ptr: *const c_uchar,
    in_ptr: *const c_uchar,
    in_len: usize,
    out_ptr: *mut c_uchar,
    tag_ptr: *mut c_uchar,
) -> c_int {
    if key_ptr.is_null() || nonce_ptr.is_null() || in_ptr.is_null() {
        return -1;
    }
    let key = unsafe { slice::from_raw_parts(key_ptr, 32) };
    let nonce = unsafe { slice::from_raw_parts(nonce_ptr, 24) };
    let plaintext = unsafe { slice::from_raw_parts(in_ptr, in_len) };
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    match cipher.encrypt(XNonce::from_slice(nonce), plaintext) {
        Ok(ciphertext) => {
            unsafe { std::ptr::copy_nonoverlapping(ciphertext.as_ptr(), out_ptr, ciphertext.len()) };
            let tag = &ciphertext[ciphertext.len() - 16..];
            unsafe { std::ptr::copy_nonoverlapping(tag.as_ptr(), tag_ptr, 16) };
            ciphertext.len() as c_int
        }
        Err(_) => -2,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn xchacha20_decrypt(
    key_ptr: *const c_uchar,
    nonce_ptr: *const c_uchar,
    in_ptr: *const c_uchar,
    in_len: usize,
    tag_ptr: *const c_uchar,
    out_ptr: *mut c_uchar,
) -> c_int {
    if key_ptr.is_null() || nonce_ptr.is_null() || in_ptr.is_null() || tag_ptr.is_null() {
        return -1;
    }
    let key = unsafe { slice::from_raw_parts(key_ptr, 32) };
    let nonce = unsafe { slice::from_raw_parts(nonce_ptr, 24) };
    let mut ciphertext = unsafe { slice::from_raw_parts(in_ptr, in_len).to_vec() };
    let tag = unsafe { slice::from_raw_parts(tag_ptr, 16) };
    ciphertext.extend_from_slice(tag);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    match cipher.decrypt(XNonce::from_slice(nonce), ciphertext.as_ref()) {
        Ok(plaintext) => {
            unsafe { std::ptr::copy_nonoverlapping(plaintext.as_ptr(), out_ptr, plaintext.len()) };
            plaintext.len() as c_int
        }
        Err(_) => -2,
    }
}
