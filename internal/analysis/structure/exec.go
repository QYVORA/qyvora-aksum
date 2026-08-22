package structure

import (
	"debug/elf"
	"errors"
)

// ErrNoExecutableRegion reports a file with no executable code to analyze.
var ErrNoExecutableRegion = errors.New("no executable code region found")

// ExecutableRegion returns the virtual base and file bytes spanning every
// allocated executable code section (.text, .init, .plt, .plt.sec, ...).
// The region is stitched from the individual sections; any alignment gaps
// are filled with INT3 so linear decoding terminates at them instead of
// inventing instructions.
func (im *Image) ExecutableRegion() (uint64, []byte, error) {
	var secs []*elf.Section
	for _, s := range im.file.Sections {
		if s.Type != elf.SHT_PROGBITS || s.Size == 0 || s.Flags&elf.SHF_EXECINSTR == 0 {
			continue
		}
		secs = append(secs, s)
	}
	if len(secs) == 0 {
		return 0, nil, ErrNoExecutableRegion
	}

	lo, hi := secs[0].Addr, secs[0].Addr+secs[0].Size
	for _, s := range secs[1:] {
		if s.Addr < lo {
			lo = s.Addr
		}
		if end := s.Addr + s.Size; end > hi {
			hi = end
		}
	}

	// INT3 padding: unreachable-by-construction filler that halts linear
	// sweeps at section boundaries rather than mis-decoding them.
	data := make([]byte, hi-lo)
	for i := range data {
		data[i] = 0xCC
	}
	buf := make([]byte, 0, 4096)
	for _, s := range secs {
		buf = buf[:cap(buf)]
		if cap(buf) < int(s.Size) {
			buf = make([]byte, s.Size)
		} else {
			buf = buf[:s.Size]
		}
		n, err := s.ReadAt(buf, 0)
		if err != nil && err.Error() != "EOF" {
			return 0, nil, err
		}
		copy(data[s.Addr-lo:], buf[:n])
	}
	return lo, data, nil
}

// PLTSection returns the virtual range of .plt.sec or .plt when present.
func (im *Image) PLTSection() (uint64, int, bool) {
	for _, name := range []string{".plt.sec", ".plt"} {
		for _, s := range im.file.Sections {
			if s.Name == name && s.Size > 0 {
				return s.Addr, int(s.Size), true
			}
		}
	}
	return 0, 0, false
}
