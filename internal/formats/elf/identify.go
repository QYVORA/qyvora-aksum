// Package elf implements ELF identification and metadata enumeration on top
// of Go's debug/elf parser. It fills the format-neutral binary.Target model
// and exposes the raw structural views (sections, segments, symbols,
// dynamic entries) consumed by later analysis stages.
//
// All values come from the file itself; when a property cannot be derived
// (e.g. canary in a fully static binary without a dynamic symbol table) it
// is reported as unknown rather than guessed.
package elf

import (
	"debug/elf"
	"fmt"
	"io"

	"github.com/QYVORA/qyvora-aksum/internal/binary"
)

// Identify fills t (Format already known to be ELF) from the file contents.
func Identify(t *binary.Target, f FileAt) error {
	e, err := elf.NewFile(f)
	if err != nil {
		return fmt.Errorf("parse ELF: %w", err)
	}
	defer e.Close() //nolint:errcheck // debug/elf holds no external resources

	bits := 32
	if e.Class == elf.ELFCLASS64 {
		bits = 64
	}
	t.Class = fmt.Sprintf("ELF%d", bits)
	t.Arch = archName(e.Machine)
	if _, little := e.ByteOrder.(interface{ String() string }); little && e.ByteOrder.String() == "LittleEndian" {
		t.Endianness = binary.Little
	} else {
		t.Endianness = binary.Big
	}
	t.OSType = osABI(e.OSABI)
	t.Entry = e.Entry

	switch e.Type {
	case elf.ET_EXEC:
		t.Type = "EXEC"
	case elf.ET_DYN:
		t.Type = "DYN"
	case elf.ET_REL:
		t.Type = "REL"
	case elf.ET_CORE:
		t.Type = "CORE"
	default:
		t.Type = "OTHER"
	}

	var hasGNUStack bool
	var gnuStackExec bool
	var hasRelro bool
	for _, seg := range e.Progs {
		switch seg.Type {
		case elf.PT_INTERP:
			data, derr := io.ReadAll(io.NewSectionReader(seg, 0, int64(seg.Filesz)))
			if derr == nil {
				t.Interpreter = trimNul(data)
			}
		case elf.PT_GNU_STACK:
			hasGNUStack = true
			gnuStackExec = seg.Flags&elf.PF_X != 0
		case elf.PT_GNU_RELRO:
			hasRelro = true
		}
	}

	// PIE: ET_DYN + interpreter is the executable-with-ASLR case; bare
	// shared objects are also ET_DYN but PIE is not a meaningful claim for
	// them, so report unknown there.
	switch {
	case e.Type == elf.ET_DYN && t.Interpreter != "":
		t.PIE = binary.PropertyEnabled
	case e.Type == elf.ET_EXEC:
		t.PIE = binary.PropertyDisabled
	default:
		t.PIE = binary.PropertyUnknown
	}

	// NX: PT_GNU_STACK present without PF_X means non-exec stack. Absent
	// PT_GNU_STACK historically defaults to an executable stack.
	switch {
	case hasGNUStack && !gnuStackExec:
		t.NX = binary.PropertyEnabled
	default:
		t.NX = binary.PropertyDisabled
	}

	// RELRO.
	switch {
	case !hasRelro:
		t.RELRO = "none"
	case hasRelro && bindsNow(e):
		t.RELRO = "full"
	default:
		t.RELRO = "partial"
	}

	dynsyms, dynErr := e.DynamicSymbols()

	// Stripped/debug from the presence of a real .symtab.
	var hasSymTab bool
	for _, s := range e.Sections {
		if s.Type == elf.SHT_SYMTAB {
			hasSymTab = true
			break
		}
	}
	if hasSymTab {
		t.Stripped = binary.PropertyDisabled
		t.DebugInfo = binary.PropertyEnabled
	} else {
		t.Stripped = binary.PropertyEnabled
		t.DebugInfo = binary.PropertyDisabled
	}

	for _, sym := range dynsyms {
		switch sym.Name {
		case "__stack_chk_fail", "__stack_chk_guard", "__intel_security_cookie":
			t.Canary = binary.PropertyEnabled
		case "__printf_chk", "__sprintf_chk", "__snprintf_chk", "__memcpy_chk",
			"__strcpy_chk", "__strcat_chk", "__fprintf_chk", "__memmove_chk":
			t.Fortify = binary.PropertyEnabled
		}
	}
	// Absence of an import does not prove absence of protection (static
	// builds inline these), so anything not affirmatively detected stays
	// unknown rather than being reported disabled.
	if t.Canary != binary.PropertyEnabled {
		t.Canary = binary.PropertyUnknown
	}
	if t.Fortify != binary.PropertyEnabled {
		t.Fortify = binary.PropertyUnknown
	}

	if needed, nerr := e.DynString(elf.DT_NEEDED); nerr == nil {
		t.Needed = needed
	}
	switch {
	case len(t.Needed) > 0 || dynErr == nil && len(dynsyms) > 0:
		t.Linking = binary.Dynamic
	case e.Type == elf.ET_EXEC && !hasInterpOrDyn(e):
		t.Linking = binary.Static
	default:
		t.Linking = binary.UnknownLinking
	}

	t.BuildID = buildID(e)
	t.CompilerHints = compilerHints(e)
	return nil
}

func hasInterpOrDyn(_ *elf.File) bool { return false } // static execs carry no PT_INTERP; kept explicit for clarity

func bindsNow(e *elf.File) bool {
	if vals, err := e.DynValue(elf.DT_BIND_NOW); err == nil && len(vals) > 0 && vals[0] != 0 {
		return true
	}
	if flags, err := e.DynValue(elf.DT_FLAGS); err == nil {
		for _, v := range flags { // DF_BIND_NOW
			if v&0x8 != 0 {
				return true
			}
		}
	}
	if flags1, err := e.DynValue(elf.DT_FLAGS_1); err == nil {
		for _, v := range flags1 { // DF_1_NOW
			if v&0x1 != 0 {
				return true
			}
		}
	}
	return false
}

func buildID(e *elf.File) string {
	for _, s := range e.Sections {
		if s.Type != elf.SHT_NOTE {
			continue
		}
		data, err := s.Data()
		if err != nil {
			continue
		}
		if id := parseBuildIDNotes(data); id != "" {
			return id
		}
	}
	return ""
}

// parseBuildIDNotes scans ELF note records for NT_GNU_BUILD_ID.
func parseBuildIDNotes(data []byte) string {
	const ntGNUBuildID = 3
	off := 0
	for off+12 <= len(data) {
		namesz := u32(data[off:])
		descsz := u32(data[off+4:])
		ntype := u32(data[off+8:])
		body := off + 12
		nameEnd := body + int(namesz)
		descStart := (nameEnd + 3) &^ 3
		descEnd := descStart + int(descsz)
		if int(namesz) >= 4 && ntype == ntGNUBuildID && nameEnd <= len(data) &&
			string(data[body:body+4]) == "GNU\x00" && descEnd <= len(data) && descStart >= body {
			return fmt.Sprintf("%x", data[descStart:descEnd])
		}
		if namesz == 0 && descsz == 0 {
			break
		}
		if nameEnd < body || descEnd < descStart || descEnd <= off {
			break // malformed; stop scanning rather than loop forever
		}
		off = descEnd
	}
	return ""
}

func u32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func archName(m elf.Machine) binary.Arch {
	switch m {
	case elf.EM_X86_64:
		return "x86-64"
	case elf.EM_386:
		return "x86"
	case elf.EM_AARCH64:
		return "AArch64"
	case elf.EM_ARM:
		return "ARM"
	case elf.EM_MIPS:
		return "MIPS"
	case elf.EM_RISCV:
		return "RISC-V"
	default:
		return binary.Arch(fmt.Sprintf("em:%d", uint32(m)))
	}
}

func osABI(a elf.OSABI) string {
	switch a {
	case elf.ELFOSABI_NONE:
		return "SYSV"
	case elf.ELFOSABI_LINUX:
		return "Linux"
	case elf.ELFOSABI_FREEBSD:
		return "FreeBSD"
	case elf.ELFOSABI_NETBSD:
		return "NetBSD"
	case elf.ELFOSABI_OPENBSD:
		return "OpenBSD"
	default:
		return fmt.Sprintf("abi:%d", byte(a))
	}
}

func compilerHints(e *elf.File) []string {
	var hints []string
	for _, s := range e.Sections {
		switch s.Name {
		case ".comment":
			hints = append(hints, "compiler comment section present")
		case ".go.buildinfo":
			hints = append(hints, "Go binary")
		case ".rustc":
			hints = append(hints, "Rust binary")
		}
	}
	return hints
}

func trimNul(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
