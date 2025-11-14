// xchacha20_poly1305_interface.h
#ifndef XCHACHA20_POLY1305_INTERFACE_H
#define XCHACHA20_POLY1305_INTERFACE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t xchacha20_encrypt(
    const uint8_t *key,     // length 32
    const uint8_t *nonce,   // length 24
    const uint8_t *in,      // plaintext
    size_t in_len,
    uint8_t *out,           // ciphertext
    uint8_t *tag            // 16 bytes auth tag
);

int32_t xchacha20_decrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *in,      // ciphertext without tag
    size_t in_len,
    const uint8_t *tag,
    uint8_t *out            // plaintext
);

#ifdef __cplusplus
}
#endif

#endif // XCHACHA20_POLY1305_INTERFACE_H
