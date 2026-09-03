// Package pe implements PE (Portable Executable) identification and metadata
// enumeration for both PE32 and PE32+ images. It fills the format-neutral
// bm.Target model and exposes the raw structural views (sections and the
// import table) consumed by later analysis stages.
//
// All values come from the file itself; when a property cannot be derived it
// is reported as unknown rather than guessed. Every header field read is
// bounds-checked so truncated or corrupt files degrade honestly instead of
// panicking.
package pe

import (
	"encoding/binary"
	"errors"
	"fmt"

	bm "github.com/QYVORA/qyvora-aksum/internal/binary"
)

// FileAt abstracts the file handle aksum hands to the PE parser: random
// access so tests can feed in-memory fixtures without a real os.File.
type FileAt interface {
	ReadAt(p []byte, off int64) (int, error)
}

// ErrNotPE reports a file whose MZ/PE signature disqualifies it as a PE
// image; callers map it to RAW degradation.
var ErrNotPE = errors.New("not a valid PE image")

// Optional-header magic values.
const (
	optMagicPE32  = 0x10b
	optMagicPE32P = 0x20b
)

// Well-known machine types.
const (
	machineI386  = 0x14c
	machineAMD64 = 0x8664
	machineARM64 = 0xaa64
	machineARM   = 0x1c0
	machineARMNT = 0x1c4
	machineIA64  = 0x200
)

// Import directory data-directory index.
const importDirIndex = 1

// Image characteristics flags (subset).
const imgFileDLL = 0x2000

// Section characteristic flags (subset).
const (
	secMemExecute = 0x20000000
	secMemRead    = 0x40000000
	secMemWrite   = 0x80000000
)

// Section is one entry of the PE section table.
type Section struct {
	Name    string   `json:"name"`
	Virtual uint64   `json:"virtual_address"`
	VSize   uint64   `json:"virtual_size"`
	Offset  uint64   `json:"raw_offset"`
	RSize   uint64   `json:"raw_size"`
	Flags   []string `json:"flags,omitempty"`
}

// Import is one imported function, grouped under its DLL. Ordinal-only
// imports carry no Name.
type Import struct {
	Name    string `json:"name,omitempty"`
	Library string `json:"library"`
	Ordinal uint16 `json:"ordinal,omitempty"`
}

// File is a parsed PE image.
type File struct {
	FileAt

	Size   int64
	Target *bm.Target

	sections     []Section
	imports      []Import
	importDirRVA uint32
	class        string
	optHdrOff    int64 // file offset of the optional header
	optBase      uint64
}

// Open parses f (size bytes) as a PE image. Non-PE files surface ErrNotPE.
func Open(f FileAt, size int64) (*File, error) {
	magic := make([]byte, 2)
	if _, err := f.ReadAt(magic, 0); err != nil {
		return nil, ErrNotPE
	}
	if magic[0] != 'M' || magic[1] != 'Z' {
		return nil, ErrNotPE
	}

	var peOff u32
	if err := readVal(f, &peOff, 0x3c); err != nil {
		return nil, ErrNotPE
	}
	sig := make([]byte, 4)
	if _, err := f.ReadAt(sig, int64(peOff)); err != nil || sig[0] != 'P' || sig[1] != 'E' {
		return nil, ErrNotPE
	}

	pf := &File{FileAt: f, Size: size, Target: &bm.Target{Format: bm.FormatPE}}

	// IMAGE_FILE_HEADER (20 bytes) right after "PE\0\0".
	hdrBase := int64(peOff) + 4
	var machine, numSections, optSize, characteristics u16
	var timestamp u32
	if err := readVal(f, &machine, hdrBase); err != nil {
		return nil, fmt.Errorf("read COFF machine: %w", err)
	}
	if err := readVal(f, &numSections, hdrBase+2); err != nil {
		return nil, fmt.Errorf("read COFF sections: %w", err)
	}
	if err := readVal(f, &timestamp, hdrBase+4); err != nil {
		return nil, fmt.Errorf("read COFF timestamp: %w", err)
	}
	if err := readVal(f, &optSize, hdrBase+16); err != nil {
		return nil, fmt.Errorf("read COFF optsize: %w", err)
	}
	if err := readVal(f, &characteristics, hdrBase+18); err != nil {
		return nil, fmt.Errorf("read COFF characteristics: %w", err)
	}

	pf.Target.Arch = archName(uint16(machine))
	pf.Target.OSType = "Windows"
	if characteristics&imgFileDLL != 0 {
		pf.Target.Type = "DLL"
	} else {
		pf.Target.Type = "EXE"
	}
	if timestamp != 0 {
		pf.Target.CompilerHints = append(pf.Target.CompilerHints, fmt.Sprintf("COFF timestamp %d", timestamp))
	}

	// IMAGE_OPTIONAL_HEADER, 20 bytes after the file header.
	optOff := hdrBase + 20
	var optMagic u16
	if err := readVal(f, &optMagic, optOff); err != nil {
		return nil, fmt.Errorf("read optional header: %w", err)
	}
	pf.optHdrOff = optOff
	switch uint16(optMagic) {
	case optMagicPE32:
		pf.Target.Class = "PE32"
		var entryRVA, imageBase u32
		if err := readVal(f, &entryRVA, optOff+16); err != nil {
			return nil, fmt.Errorf("read PE32 entry: %w", err)
		}
		if err := readVal(f, &imageBase, optOff+28); err != nil {
			return nil, fmt.Errorf("read PE32 image base: %w", err)
		}
		pf.Target.Entry = uint64(entryRVA)
		pf.optBase = uint64(imageBase)
	case optMagicPE32P:
		pf.Target.Class = "PE32+"
		var entryRVA u32
		var imageBase u64
		if err := readVal(f, &entryRVA, optOff+16); err != nil {
			return nil, fmt.Errorf("read PE32+ entry: %w", err)
		}
		if err := readVal(f, &imageBase, optOff+24); err != nil {
			return nil, fmt.Errorf("read PE32+ image base: %w", err)
		}
		pf.Target.Entry = uint64(entryRVA)
		pf.optBase = uint64(imageBase)
	default:
		return nil, fmt.Errorf("unrecognized optional-header magic %#x", optMagic)
	}
	pf.class = pf.Target.Class

	if err := pf.readSections(uint16(numSections), hdrBase+20+int64(optSize)); err != nil {
		return nil, err
	}
	pf.readDataDirs()
	pf.readImports()
	return pf, nil
}

// Identify fills t (Format already known to be PE) from the file contents.
// It parses the image and copies every determinable property onto t,
// preserving the path/size/hash fields the loader set beforehand. parseErr
// reports when the container matched MZ/PE magic but its content was
// unparseable, so the caller can degrade honestly to RAW.
func Identify(t *bm.Target, f FileAt, size int64) (parseErr error) {
	pf, err := Open(f, size)
	if err != nil {
		return err
	}
	t.Class = pf.Target.Class
	t.Arch = pf.Target.Arch
	t.OSType = pf.Target.OSType
	t.Type = pf.Target.Type
	t.Entry = pf.Target.Entry
	t.Linking = bm.Dynamic // PE imports resolve through DLLs by construction
	t.Needed = pf.Needed()
	t.CompilerHints = append(t.CompilerHints, pf.Target.CompilerHints...)
	return nil
}

// optBase records ImageBase. aksum's neutral Target stores entry as an RVA,
// but ImageBase is retained here so callers can reconstruct absolute VA when
// needed.

// readSections reads the section table located at tableOff.
func (pf *File) readSections(numSections uint16, tableOff int64) error {
	for i := 0; i < int(numSections); i++ {
		off := tableOff + int64(i)*40
		var name [8]byte
		if _, err := pf.ReadAt(name[:], off); err != nil {
			return fmt.Errorf("read section %d name: %w", i, err)
		}
		var vsize, va, rsize, roff, chars u32
		if err := readVal(pf, &vsize, off+8); err != nil {
			return err
		}
		if err := readVal(pf, &va, off+12); err != nil {
			return err
		}
		if err := readVal(pf, &rsize, off+16); err != nil {
			return err
		}
		if err := readVal(pf, &roff, off+20); err != nil {
			return err
		}
		if err := readVal(pf, &chars, off+36); err != nil {
			return err
		}
		pf.sections = append(pf.sections, Section{
			Name:    trimNul(name[:]),
			Virtual: uint64(va),
			VSize:   uint64(vsize),
			Offset:  uint64(roff),
			RSize:   uint64(rsize),
			Flags:   sectionFlags(uint32(chars)),
		})
	}
	return nil
}

// readDataDirs captures the import directory RVA from the optional header's
// data-directory array.
func (pf *File) readDataDirs() {
	var numDirs u32
	var numOff int64
	if pf.class == "PE32" {
		numOff = 92
	} else {
		numOff = 108
	}
	if err := readVal(pf, &numDirs, pf.optHdrOff+numOff); err != nil {
		return
	}
	if uint32(numDirs) <= importDirIndex {
		return
	}
	dirBase := pf.optHdrOff + numOff + 4
	var rva, size u32
	if err := readVal(pf, &rva, dirBase+int64(importDirIndex)*8); err != nil {
		return
	}
	if err := readVal(pf, &size, dirBase+int64(importDirIndex)*8+4); err != nil {
		return
	}
	_ = size
	pf.importDirRVA = uint32(rva)
}

// readImports walks the import directory and resolves named imports.
func (pf *File) readImports() {
	if pf.importDirRVA == 0 {
		return
	}
	out := make([]Import, 0, 64)
	entrySize := uint32(8)
	if pf.class == "PE32" {
		entrySize = 4
	}
	for dir := 0; dir < 1024; dir++ {
		off := pf.rvaToFile(int64(pf.importDirRVA) + int64(dir)*20)
		if off < 0 {
			break
		}
		var origFirstThunk, nameRVA, firstThunk u32
		if err := readVal(pf, &origFirstThunk, off); err != nil {
			break
		}
		if err := readVal(pf, &nameRVA, off+12); err != nil {
			break
		}
		if err := readVal(pf, &firstThunk, off+16); err != nil {
			break
		}
		if uint32(origFirstThunk) == 0 && uint32(nameRVA) == 0 && uint32(firstThunk) == 0 {
			break // terminator reached
		}
		dll := pf.readCString(uint32(nameRVA))
		thunkRVA := uint32(firstThunk)
		if thunkRVA == 0 {
			thunkRVA = uint32(origFirstThunk)
		}
		if thunkRVA == 0 || dll == "" {
			continue
		}
		for th := 0; th < 4096; th++ {
			tOff := pf.rvaToFile(int64(thunkRVA) + int64(th)*int64(entrySize))
			if tOff < 0 {
				break
			}
			// IMAGE_THUNK_DATA is 4 bytes on PE32 and 8 on PE32+.
			var v uint64
			if pf.class == "PE32" {
				var raw u32
				if err := readVal(pf, &raw, tOff); err != nil {
					break
				}
				v = uint64(raw)
			} else {
				var raw u64
				if err := readVal(pf, &raw, tOff); err != nil {
					break
				}
				v = uint64(raw)
			}
			if v == 0 {
				break // end of thunk array
			}
			// Ordinal import is signalled by the high bit.
			if (pf.class == "PE32+" && v&(1<<63) != 0) || (pf.class == "PE32" && v&(1<<31) != 0) {
				out = append(out, Import{Ordinal: uint16(v & 0xffff), Library: dll})
				continue
			}
			nameOff := pf.rvaToFile(int64(v))
			if nameOff < 0 {
				continue
			}
			// IMAGE_IMPORT_BY_NAME {Hint(2 bytes); Name}.
			name := pf.readCStringAt(nameOff + 2)
			if name != "" {
				out = append(out, Import{Name: name, Library: dll})
			}
		}
	}
	pf.imports = out
}

// rvaToFile converts a relative virtual address to a file offset by locating
// the containing section, or -1 when unmapped.
func (pf *File) rvaToFile(rva int64) int64 {
	for _, s := range pf.sections {
		if s.RSize == 0 {
			continue
		}
		if rva >= int64(s.Virtual) && rva < int64(s.Virtual)+int64(s.VSize) {
			return int64(s.Offset) + (rva - int64(s.Virtual))
		}
	}
	return -1
}

func (pf *File) readCString(rva uint32) string {
	off := pf.rvaToFile(int64(rva))
	if off < 0 {
		return ""
	}
	return pf.readCStringAt(off)
}

func (pf *File) readCStringAt(off int64) string {
	var buf []byte
	for i := 0; i < 4096; i++ {
		var b [1]byte
		if _, err := pf.ReadAt(b[:], off+int64(i)); err != nil {
			break
		}
		if b[0] == 0 {
			return string(buf)
		}
		buf = append(buf, b[0])
	}
	return string(buf)
}

// Sections returns the parsed section table.
func (pf *File) Sections() []Section { return pf.sections }

// Imports returns the resolved named/ordinal imports.
func (pf *File) Imports() []Import { return pf.imports }

// Needed returns the distinct import libraries (DLLs) this image depends on.
func (pf *File) Needed() []string {
	seen := map[string]bool{}
	var out []string
	for _, im := range pf.imports {
		if im.Library != "" && !seen[im.Library] {
			seen[im.Library] = true
			out = append(out, im.Library)
		}
	}
	return out
}

// archName maps the COFF machine value to aksum's architecture string.
func archName(m uint16) bm.Arch {
	switch m {
	case machineAMD64:
		return "x86-64"
	case machineI386:
		return "x86"
	case machineARM64:
		return "AArch64"
	case machineARM, machineARMNT:
		return "ARM"
	case machineIA64:
		return "Itanium"
	default:
		return bm.Arch(fmt.Sprintf("machine:%#x", m))
	}
}

func trimNul(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func sectionFlags(c uint32) []string {
	var out []string
	if c&secMemRead != 0 {
		out = append(out, "R")
	}
	if c&secMemWrite != 0 {
		out = append(out, "W")
	}
	if c&secMemExecute != 0 {
		out = append(out, "X")
	}
	return out
}

// Fixed-width scalar wrappers make the readVal type switch unambiguous.
type u16 uint16
type u32 uint32
type u64 uint64

// readVal reads one little-endian fixed-width value at off.
func readVal(f FileAt, dst any, off int64) error {
	switch v := dst.(type) {
	case *u16:
		var b [2]byte
		if _, err := f.ReadAt(b[:], off); err != nil {
			return err
		}
		*v = u16(binary.LittleEndian.Uint16(b[:]))
	case *u32:
		var b [4]byte
		if _, err := f.ReadAt(b[:], off); err != nil {
			return err
		}
		*v = u32(binary.LittleEndian.Uint32(b[:]))
	case *u64:
		var b [8]byte
		if _, err := f.ReadAt(b[:], off); err != nil {
			return err
		}
		*v = u64(binary.LittleEndian.Uint64(b[:]))
	default:
		return fmt.Errorf("readVal: unsupported type %T", dst)
	}
	return nil
}
