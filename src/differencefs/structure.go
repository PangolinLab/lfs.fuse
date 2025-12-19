package differencefs

const (
	Xdelta = iota
	Myers
)

type DifferenceChunk struct {
	Content []byte
	Algo    uint8
}
