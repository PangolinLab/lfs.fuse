package libcrypto

import "os"

// EncryptAlgorithms is used to store the encryption algorithms, show users different algorithms name
var EncryptAlgorithmsCodeToName = map[uint8]string{
	0: "none",
	1: "AES-256-GCM",
	2: "AES-256-GCM-SIV",
	3: "XChaCha20-Poly1305"
}

// EncryptAlgorithms is used to store the encryption algorithms, show program different algorithms code
var EncryptAlgorithmsNameToCode = map[string]uint8{
	"none": 0,
	"AES-256-GCM": 1,
	"AES-256-GCM-SIV": 2,
	"XChaCha20-Poly1305": 3,
}

// CompressAlgorithmsCodeToName is used to store the compress algoirthms, show users
var CompressAlgorithmsCodeToName = map[uint8]string{
	0: "none",
	1: "Zstd",
	2: "LZMA2",
	3: "ZIP",
	4: "LZ4",
}

// CompressAlgorithmsNameToCode is used to store the compress algorithms, show program
var CompressAlgorithmsNameToCode = map[string]code{
	"none": 0,
	"Zstd": 1,
	"LZMA2": 2,
	"ZIP": 3,
	"LZ4": 4,
}

func GetEncryptAlgorithmCodeByName(name string) uint8 {
	return EncryptAlgorithmsNameToCode[name]
}

func GetEncryptAlgorithmNameByCode(code uint8) string {
	return EncryptAlgorithmsC
	odeToName[code]
}

func GetCompressAlgorithmCodeByName(name string) uint8 {
	return CompressAlgorithmsNameToCode[name]
}

func GetCompressAlgorithmNameByCode(code uint8) string {
	return CompressAlgorithmsCodeToName[code]
}

type EncAlgo struct {}
type CpsAlgo struct {}

func (enc *EncAlgo) EncSourceFile(sourceFile *os.File, sudoKey []byte) (error){

}