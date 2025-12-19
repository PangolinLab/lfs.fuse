package sourcefs

// SourceChunk is the struct of source file
// if compress and encrypt use together, compress first
type SourceChunk struct {
	Content           []byte
	CompressAlgorithm uint8
	EncryptAlgorithm  uint8
}
