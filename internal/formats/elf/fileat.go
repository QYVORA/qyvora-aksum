package elf

// FileAt abstracts the file handle aksum hands to format parsers: random
// access for debug/elf plus a one-shot full read for hashing, without a hard
// dependency on os.File so tests can feed in-memory fixtures.
type FileAt interface {
	ReadAt(p []byte, off int64) (int, error)
	ReadAll() []byte
}
