package linkfs

import "time"

const (
	Read = iota
	Write
	Append
	Execute
	Truncate
	Shared    // 允许并发读
	Exclusive //独占访问（读写都锁）
	LockAll   // 禁止任何操作，除非使用 XLFS 解锁
)

const (
	Text = iota
	Binary
	Media
	Compressed
	Document
	Script
)

// LinkChunk is the structure of Link File
type LinkChunk struct {
	Sources        []string //filenames
	Difference     string   // filename
	AttributesData FileAttributes
}

type FileAttributes struct {
	Name            string
	Size            uint64
	TypeSpeculation string
	Timestamps      Timestamps
	Permissions     uint8
	Describe        string
}

type Timestamps struct {
	Creation         time.Time
	LastModification time.Time
	LastAccess       time.Time
	TTLDuration      time.Duration
}
