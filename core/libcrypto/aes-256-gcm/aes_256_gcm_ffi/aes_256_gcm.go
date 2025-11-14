package aes_256_gcm_ffi

/*
	#cgo CFLAGS: -I${SRCDIR}/include
	#cgo LDFLAGS: -lkernel32 -lntdll -luserenv -lws2_32 -ldbghelp -L${SRCDIR}/bin -laes_256_gcm
	#include <stdlib.h>
	#include <aes_256_gcm_interface.h>
*/
import "C"
import (
	"encoding/hex"
	"errors"
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

// safeCString creates a C string and ensures memory is freed even on panic.
func safeCString(s string) (*C.char, func()) {
	cStr := C.CString(s)
	return cStr, func() { C.free(unsafe.Pointer(cStr)) }
}

func AES256GCMEncrypt(key, nonce, plaintext []byte) ([]byte, error) {
	keyLen := len(key)
	if keyLen != 32 {
		return nil, errors.New("invalid aes-256-gcm key length: 32 bytes, receive ", keyLen)
	}
	nonceLen := len(nonce)
	if nonceLen != 12 {
		return nil, errors.New("invalid aes-256-gcm key length: 12 bytes, receive: ", nonceLen)
	}
	if plaintext == nil {
		return nil, errors.New("invalid aes-256-gcm plaintext: not be nil")
	}

	// 转 hex
	keyHexStr := hex.EncodeToString(key)
	nonceHexStr := hex.EncodeToString(nonce)
	ptHexStr := hex.EncodeToString(plaintext)

	// C string
	keyHex, freeKey := safeCString(keyHexStr)
	nonceHex, freeNonce := safeCString(nonceHexStr)
	ptHex, freePt := safeCString(ptHexStr)
	defer freeKey()
	defer freeNonce()
	defer freePt()

	// 调 Rust
	res := C.aes_256_gcm_encrypt(keyHex, nonceHex, ptHex)
	if res == nil {
		return nil, errors.New("aes-256-gcm encryption failed")
	}
	defer C.aes_256_gcm_free(res)

	// 解析结果
	outHex := C.GoString(res)
	ct, err := hex.DecodeString(outHex)
	if err != nil {
		return nil, err
	}

	// 返回 nonce||ct
	final := append(nonce, ct...)
	return final, nil
}

func AES256GCMDecrypt(key, combined []byte) ([]byte, error) {
	keyLen := len(key)
	if keyLen != 32{
		return nil, errors.New("invalid aes-256-gcm key length: 32 bytes, receive ", keyLen)
	}
	combinedLen := len(combined)
	if combinedLen <= 12 {
		return nil, errors.New("invalid aes-256-gcm nonce and ciphertext length: more than 12 bytes, receive ", combinedLen)
	}

	// 拆分 nonce 和 ct
	nonce := combined[:12]
	ciphertext := combined[12:]

	// 转 hex
	keyHexStr := hex.EncodeToString(key)
	nonceHexStr := hex.EncodeToString(nonce)
	ctHexStr := hex.EncodeToString(ciphertext)

	keyHex, freeKey := safeCString(keyHexStr)
	nonceHex, freeNonce := safeCString(nonceHexStr)
	ctHex, freeCt := safeCString(ctHexStr)
	defer freeKey()
	defer freeNonce()
	defer freeCt()

	// 调 Rust
	res := C.aes_256_gcm_decrypt(keyHex, nonceHex, ctHex)
	if res == nil {
		return nil, errors.New("aes-256-gcm decryption failed")
	} 
	defer C.aes_256_gcm_free(res)

	outHex := C.GoString(res)
	ok, err := isValidHex(outHex)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("invalid hex output from aes-256-gcm decryption")
	}
	return hex.DecodeString(outHex)
}
