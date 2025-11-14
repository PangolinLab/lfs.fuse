#ifndef AES_256_GCM_INTERFACE_H
#define AES_256_GCM_INTERFACE_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

char* aes_256_gcm_siv_decrypt(
    const char* key_hex,
    const char* nonce_hex,
    const char* ciphertext_hex
);

char* aes_256_gcm_siv_encrypt(
    const char* key_hex,
    const char* nonce_hex,
    const char* plaintext_hex
);

void aes_256_gcm_siv_free(char* ptr);

#ifdef __cplusplus
}
#endif

#endif // AES_256_GCM_INTERFACE_H
