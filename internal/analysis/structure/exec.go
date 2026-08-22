package structure

import (
	"debug/elf"
	"errors"
)

// ErrNoExecutableRegion reports a file with no executable code to analyze.
var ErrNoExecutableRegion = errors.New("no executable code region found")

// ExecutableRegion returns the virtual base and file bytes of the primary
// executable code region (.text when present, else the first allocated
// SHF_EXECINSTR PROGBITS section).
func (im *Image) ExecutableRegion() (uint64, []byte, error) {
	var chosen *elf.Section
	for _, s := range im.file.Sections {
		if s.Type != elf.SHT_PROGBITS || s.Size == 0 || s.Flags&elf.SHF_EXECINSTR == 0 {
			continue
		}
		if chosen == nil || s.Name == ".text" {
			chosen = s
			if s.Name == ".text" {
				break
			}
		}
	}
	if chosen == nil {
		return 0, nil, ErrNoExecutableRegion
	}
	data := make([]byte, chosen.Size)
	n, err := chosen.ReadAt(data, 0)
	if err != nil && err.Error() != "EOF" {
		return 0, nil, err
	}
	return chosen.Addr, data[:n], nil
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
