package loader

import "os"

// fileAt adapts *os.File to the format layer's needs (random access plus a
// full read for hashing).
type fileAt struct{ f *os.File }

func (fa *fileAt) ReadAt(p []byte, off int64) (int, error) { return fa.f.ReadAt(p, off) }

// ReadAll returns the entire file for hashing. Files above 2 GiB are refused
// (hashing unbounded input is a resource-exhaustion vector; spec section 50).
func (fa *fileAt) ReadAll() []byte {
	st, err := fa.f.Stat()
	if err != nil || st.Size() <= 0 || st.Size() > 1<<31 {
		return nil
	}
	if _, err := fa.f.Seek(0, 0); err != nil {
		return nil
	}
	buf := make([]byte, st.Size())
	n, _ := fa.f.Read(buf)
	return buf[:n]
}

func ioReadFull(f *os.File, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := f.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
