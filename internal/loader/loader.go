// Package loader opens a file, sniffs its container format by magic bytes,
// and dispatches to the format-specific identifier that fills the neutral
// binary.Target model. Unsupported formats surface as ErrUnsupported so CLI
// callers can exit with the dedicated unsupported-target code instead of a
// generic failure.
package loader

import (
	"errors"
	"fmt"
	"os"

	"github.com/QYVORA/qyvora-aksum/internal/binary"
	"github.com/QYVORA/qyvora-aksum/internal/formats/elf"
)

// ErrUnsupported reports a recognized-but-unimplemented container format.
var ErrUnsupported = errors.New("unsupported binary format")

// Open reads path, identifies it, and returns the populated Target.
func Open(path string) (*binary.Target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only handle on success path

	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}

	magic := make([]byte, 4)
	if _, err := ioReadFull(f, magic); err != nil {
		return nil, fmt.Errorf("%s: too small to contain a known format header (%d bytes)", path, st.Size())
	}

	t := &binary.Target{Path: path, Size: st.Size()}
	switch {
	case magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F':
		t.Format = binary.FormatELF
		if err := elf.Identify(t, &fileAt{f: f}); err != nil {
			return nil, err
		}
	default:
		// Honest limitation: no parser for this container yet. Strings-only
		// RAW analysis remains possible; identification is not offered.
		t.Format = binary.FormatRaw
		return t, nil
	}
	return t, nil
}
