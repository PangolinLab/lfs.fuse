package xchacha20_poly1305_ffi

import (
	"core/csx/contracts"
	"errors"
	"unsafe"
)

/*
	#cgo CFLAGS: -I${SRCDIR}/include
	#cgo LDFLAGS: -lkernel32 -lntdll -luserenv -lws2_32 -ldbghelp -L${SRCDIR}/bin -lxchacha20_poly1305
	#include "xchacha20_poly1305_interface.h"
*/
import "C"

func (x *XChaCha20Poly1305Impl) XChaCha20Poly1305Encrypt(key, nonce, plaintext []byte) ([]byte, error) {
	if len(key) != 32 || len(nonce) != 24 {
		return nil, errors.New("invalid key or nonce length")
	}
	if len(plaintext) == 0 {
		return nil, errors.New("plaintext cannot be empty")
	}

	ciphertext := make([]byte, len(plaintext)+32)
	tag := make([]byte, 16)

	ret := C.xchacha20_encrypt(
		(*C.uint8_t)(unsafe.Pointer(&key[0])),
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])),
		(*C.uint8_t)(unsafe.Pointer(&plaintext[0])),
		C.size_t(len(plaintext)),
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),
		(*C.uint8_t)(unsafe.Pointer(&tag[0])),
	)

	if ret < 0 {
		return nil, errors.New("encrypt error")
	}
	if int(ret) > len(ciphertext) {
		return nil, errors.New("returned length invalid")
	}

	return append(append(ciphertext[:ret], tag...), nonce...), nil
}

func (x *XChaCha20Poly1305Impl) XChaCha20Poly1305Decrypt(key, ciphertextAndTagAndNonce []byte) ([]byte, error) {
	if len(key) != 32 || len(ciphertextAndTagAndNonce) < 16+24 {
		return nil, errors.New("invalid lengths")
	}

	// 拆分 nonce、ciphertext 和 tag
	nonce := ciphertextAndTagAndNonce[len(ciphertextAndTagAndNonce)-24:]
	ciphertextAndTag := ciphertextAndTagAndNonce[:len(ciphertextAndTagAndNonce)-24]
	if len(ciphertextAndTag) < 16 {
		return nil, errors.New("ciphertextAndTag too short")
	}
	ciphertext := ciphertextAndTag[:len(ciphertextAndTag)-16]
	tag := ciphertextAndTag[len(ciphertextAndTag)-16:]

	out := make([]byte, len(ciphertext))
	ret := C.xchacha20_decrypt(
		(*C.uint8_t)(unsafe.Pointer(&key[0])),
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])),
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),
		C.size_t(len(ciphertext)),
		(*C.uint8_t)(unsafe.Pointer(&tag[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)
	if ret < 0 {
		return nil, errors.New("decrypt error or authentication failed")
	}
	return out[:ret], nil
}
