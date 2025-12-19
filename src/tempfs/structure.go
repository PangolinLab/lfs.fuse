package tempfs

const (
	Complete = iota
	OnlySource
)

const (
	MemoryL1 = iota
	MemoryL2
	DiskL3
	DiskL4
)

type TempChunk struct {
	Content   []byte
	Situation uint8
	HotLevel  uint8
}
