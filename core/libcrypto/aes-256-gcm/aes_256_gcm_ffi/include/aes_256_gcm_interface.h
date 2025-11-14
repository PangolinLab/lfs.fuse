#ifndef AES_256_GCM_INTERFACE_H
#define AES_256_GCM_INTERFACE_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/// AES-256-GCM Encryption
/// Parameters:
/// - key_hex: 64-character 32-byte key (hex encoded, ASCII, valid [0-9a-fA-F], null-terminated)
/// - nonce_hex: 24-character 12-byte nonce (hex encoded, ASCII, valid [0-9a-fA-F], null-terminated)
/// - plaintext_hex: Plaintext of arbitrary length (hex encoded, ASCII, valid [0-9a-fA-F], null-terminated)
/// Returns:
/// - Success: Returns hex-encoded ciphertext+tag (must be freed with `aes_gcm_free` after use)
/// - Failure: Returns NULL (invalid input, key/nonce length, or encryption failure)
/// Safety:
/// - Inputs must be valid UTF-8 and null-terminated C strings.
/// - Caller must free returned pointer with `aes_gcm_free` to avoid memory leaks.
char* aes_256_gcm_encrypt(const char* key_hex, const char* nonce_hex, const char* plaintext_hex);

/// AES-GCM-256 Decryption
/// Parameters:
/// - key_hex: 64-character 32-byte key (hex encoded, ASCII, valid [0-9a-fA-F], null-terminated)
/// - nonce_hex: 24-character 12-byte nonce (hex encoded, ASCII, valid [0-9a-fA-F], null-terminated)
/// - ciphertext_hex: Ciphertext+tag of arbitrary length (hex encoded, ASCII, valid [0-9a-fA-F], null-terminated)
/// Returns:
/// - Success: Returns hex-encoded plaintext (must be freed with `aes_gcm_free` after use)
/// - Failure: Returns NULL (invalid input, key/nonce length, or decryption failure)
/// Safety:
/// - Inputs must be valid UTF-8 and null-terminated C strings.
/// - Caller must free returned pointer with `aes_gcm_free` to avoid memory leaks.
char* aes_256_gcm_decrypt(const char* key_hex, const char* nonce_hex, const char* ciphertext_hex);

/// Release the string returned by aes_gcm_encrypt or aes_gcm_decrypt
/// Parameter: ptr is the pointer to the result returned by encryption or decryption
/// Safety:
/// - Safe to call with NULL pointer.
/// - Do not free the same pointer twice.
void aes_256_gcm_free(char* ptr);

#ifdef __cplusplus
}
#endif

#endif // AES_256_GCM_INTERFACE_H