package source_part

import ( 
	"time"
	"encoding/gob"
)

// if compress and encrypt use together, compress first
type SourceChunk struct {
    Data []byte
	CompressAlgorithm uint8
	EncryptAlgorithm uint8
	Timestamp time.time
}

type SourceChunkOperator struct {}

// BytesToStruct convert source file bytes to struct
func (scop *SourceChunkOperator) BytesToStruct(sourceFileBytes []byte) (*SourceChunk, error){
	var buf bytes.Buffer
	buf.Write(sourceFileBytes)

	var chunk SourceChunk
	dec := gob.NewDecoder(&buf)

	if err := dec.Decode(&chunk); err != nil {
		return nil, err
	}
	return &chunk, nil
}

// StructToBytes convert source file struct to bytes
func (scop *SourceChunkOperator) StructToBytes(chunk *SourceChunk) ([]byte, error){
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	if err := enc.Encode(chunk); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (scop *SourceChunkOperator) EncryptOnly(chunk *SourceChunk, sudoKey []byte) error {
	// get algo
	algo := chunk.EncryptAlgorithm

	// get data
	data := chunk.Data

	switch algo {
	case 0:
		// do nothing
	case 1:
		// AES-256-GCM
		// generate a nonce
		nonce := make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		ctWithNonce, err := aes_256_gcm_ffi.AES256GCMEncrypt(sudoKey, nonce, data)
		if err != nil {
			return err
		}
		data = ctWithNonce
	case 2:
		// AES-256-GCM-SIV
		// generate a nonce
		nonce := make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		ctWithNonce, err := aes_256_gcm_siv_ffi.AES256GCMSIVEncrypt(sudoKey, nonce, data)
		if err != nil {
			return err
		}
		data = ctWithNonce
	case 3:
		// XChaCha20-Poly1305
		// generate a nonce
		nonce := make([]byte, 24)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		ctWithNonce, err := xchacha20_poly1305_ffi.XChaCha20Poly1305Encrypt(sudoKey, nonce, data)
		if err != nil {
			return err
		}
		data = ctWithNonce
	default:
		return errors.New("unsupported encrypt algorithm")
	}
	return nil
}

func (scop *SourceChunkOperator) DecryptOnly(chunk *SourceChunk, sudoKey []byte) error {
	algo := chunk.EncryptAlgorithm

	data := chunk.Data

	switch algo {
	case 0:
		// do nothing
	case 1:
		// AES-256-GCM
		pt, err := aes_256_gcm_ffi.AES256GCMDecrypt(sudoKey, data)
		if err != nil {
			return err
		}
		data = pt
	case 2:
		// AES-256-GCM-SIV
		pt, err := aes_256_gcm_siv_ffi.AES256GCMSIVDecrypt(sudoKey, data)
		if err != nil {
			return err
		}
		data = pt
	case 3:
		// XChaCha20-Poly1305
		pt, err := xchacha20_poly1305_ffi.XChaCha20Poly1305Decrypt(sudoKey, data)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported encrypt algorithm")
	}
}

func (scop *SourceChunkOperator) CompressOnly(chunk *SourceChunk) error {
	
}