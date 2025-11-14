package aes_256_gcm_siv_ffi

/*
	#cgo CFLAGS: -I${SRCDIR}/include
	#cgo LDFLAGS: -lkernel32 -lntdll -luserenv -lws2_32 -ldbghelp -L${SRCDIR}/bin -laes_256_gcm_siv
	#include <stdlib.h>
	#include <aes_256_gcm_siv_interface.h>
*/
import "C"
import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"unsafe"
)

func isValidHex(s string) (bool, error) {
	if s == "" {
		return false, errors.New("empty string")
	}
	if len(s)%2 != 0 {
		return false, nil
	}
	matched, _ := regexp.MatchString("^[0-9a-fA-F]+$", s)
	if !matched {
		return false, nil
	}
	_, err := hex.DecodeString(s)
	return err == nil, nil
}

func AES256GCMSIVEncrypt(key, nonce, plaintext []byte) ([]byte, error) {
	keyLen := len(key)
	if keyLen != 32 {
		return nil, errors.New("invalid aes-256-gcm-siv encryption key length: 32 bytes, receive ", keyLen)
	}
	nonceLen := len(nonce)
	if nonceLen != 12 {
		return nil, errors.New("invalid aes-256-gcm-siv encryption nonce length: 12 bytes, receive ", nonceLen)
	}
	if plaintext == nil {
		return nil, errors.New("invalid aes-256-gcm-siv encryption plaintext: not be nil")
	}

	// 转 hex
	keyHex := hex.EncodeToString(key)
	nonceHex := hex.EncodeToString(nonce)
	ptHex := hex.EncodeToString(plaintext)

	cKey := C.CString(keyHex)
	defer C.free(unsafe.Pointer(cKey))
	cNonce := C.CString(nonceHex)
	defer C.free(unsafe.Pointer(cNonce))
	cPt := C.CString(ptHex)
	defer C.free(unsafe.Pointer(cPt))

	// 调 Rust
	res := C.aes_256_gcm_siv_encrypt(cKey, cNonce, cPt)
	if res == nil {
		return nil, errors.New("aes-256-gcm-siv encryption failed")
	}
	defer C.aes_256_gcm_siv_free(res)

	// 输出 hex
	outHex := C.GoString(res)
	ok, err := isValidHex(outHex)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("invalid hex output from aes-256-gcm-siv encryption")
	}
	ct, _ := hex.DecodeString(outHex)

	// 合并 nonce || ciphertext
	return append(nonce, ct...), nil
}

func AES256GCMSIVDecrypt(key, nonceCt []byte) ([]byte, error) {
	keyLen := len(key)
	if keyLen != 32 {
		return nil, errors.New("invalid aes-256-gcm-siv decryption input key length: 32 bytes, receive ", keyLen)
	}
	nonceCtLen := len(nonceCt)
	if nonceCtLen <= 12{
		return nil, errors.New("invalid aes-256-gcm-siv decryption input nonce and ciphertext length: more than 12 bytes, receive ", nonceCtLen)
	}

	// 分离 nonce / ct
	nonce := nonceCt[:12]
	ct := nonceCt[12:]

	// 转 hex
	keyHex := hex.EncodeToString(key)
	nonceHex := hex.EncodeToString(nonce)
	ctHex := hex.EncodeToString(ct)

	cKey := C.CString(keyHex)
	defer C.free(unsafe.Pointer(cKey))
	cNonce := C.CString(nonceHex)
	defer C.free(unsafe.Pointer(cNonce))
	cCt := C.CString(ctHex)
	defer C.free(unsafe.Pointer(cCt))

	// 调 Rust
	res := C.aes_256_gcm_siv_decrypt(cKey, cNonce, cCt)
	if res == nil {
		return nil, errors.New("aes-256-gcm-siv decryption failed")
	}
	defer C.aes_256_gcm_siv_free(res)

	outHex := C.GoString(res)
	ok, err := isValidHex(outHex)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("invalid hex output from aes-256-gcm-siv decryption")
	}
	return hex.DecodeString(outHex)
}