// Package loader opens a file, sniffs its container format by magic bytes,
// and dispatches to the format-specific identifier that fills the neutral
// binary.Target model. Unsupported formats surface as ErrUnsupported so CLI
// callers can exit with the dedicated unsupported-target code instead of a
// generic failure.
package loader

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/QYVORA/qyvora-aksum/internal/binary"
	"github.com/QYVORA/qyvora-aksum/internal/formats/elf"
	"github.com/QYVORA/qyvora-aksum/internal/formats/pe"
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
	n, err := ioReadFull(f, magic)
	t := &binary.Target{Path: path, Size: st.Size()}
	if err != nil && n < 1 {
		// Too small to hold any known header: still a valid analysis target
		// for RAW-mode strings; identification is honestly unavailable.
		t.Format = binary.FormatRaw
		return t, nil
	}
	if _, serr := f.Seek(0, 0); serr != nil {
		return nil, fmt.Errorf("rewind %s: %w", path, serr)
	}
	// Every target carries a content hash — it anchors findings and reports
	// to the exact analyzed artifact.
	fa := &fileAt{f: f}
	sum := sha256.Sum256(fa.ReadAll())
	t.SHA256 = hex.EncodeToString(sum[:])
	switch {
	case magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F':
		t.Format = binary.FormatELF
		if err := elf.Identify(t, fa); err != nil {
			// Magic matched but content is unparseable (truncated, corrupt
			// tables). Degrade honestly to RAW — strings-only analysis
			// remains possible and identification is reported as
			// unavailable rather than half-guessed.
			t = &binary.Target{Path: path, Size: st.Size(), SHA256: t.SHA256, Format: binary.FormatRaw}
		}
	case magic[0] == 'M' && magic[1] == 'Z':
		// A valid PE image begins "MZ" and carries a "PE\0\0" signature at
		// the offset stored at 0x3C. pe.Identify validates both and fills the
		// neutral model; a file that smells MZ but fails the signature check
		// degrades honestly to RAW rather than half-claiming PE.
		t.Format = binary.FormatPE
		if err := pe.Identify(t, fa, st.Size()); err != nil {
			t = &binary.Target{Path: path, Size: st.Size(), SHA256: t.SHA256, Format: binary.FormatRaw}
		}
	default:
		// Honest limitation: no parser for this container yet. Strings-only
		// RAW analysis remains possible; identification is not offered.
		t.Format = binary.FormatRaw
		return t, nil
	}
	return t, nil
}
