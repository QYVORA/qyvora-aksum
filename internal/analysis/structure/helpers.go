package structure

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
)

// splitVersion separates "@GLIBC_2.34" style version suffixes.
func splitVersion(name string) (base, version string) {
	if i := indexOfByte(name, '@'); i >= 0 {
		return name[:i], name[i+1:]
	}
	return name, ""
}

func indexOfByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func sectionTypeName(t elf.SectionType) string {
	switch t {
	case elf.SHT_NULL:
		return "NULL"
	case elf.SHT_PROGBITS:
		return "PROGBITS"
	case elf.SHT_SYMTAB:
		return "SYMTAB"
	case elf.SHT_STRTAB:
		return "STRTAB"
	case elf.SHT_RELA:
		return "RELA"
	case elf.SHT_HASH:
		return "HASH"
	case elf.SHT_DYNAMIC:
		return "DYNAMIC"
	case elf.SHT_NOTE:
		return "NOTE"
	case elf.SHT_NOBITS:
		return "NOBITS"
	case elf.SHT_REL:
		return "REL"
	case elf.SHT_DYNSYM:
		return "DYNSYM"
	case elf.SHT_GNU_HASH:
		return "GNU_HASH"
	default:
		return fmt.Sprintf("0x%x", uint32(t))
	}
}

func sectionFlagNames(f elf.SectionFlag) []string {
	var out []string
	add := func(cond bool, name string) {
		if cond {
			out = append(out, name)
		}
	}
	add(f&elf.SHF_WRITE != 0, "W")
	add(f&elf.SHF_ALLOC != 0, "A")
	add(f&elf.SHF_EXECINSTR != 0, "X")
	add(f&elf.SHF_MERGE != 0, "M")
	add(f&elf.SHF_STRINGS != 0, "S")
	add(f&elf.SHF_TLS != 0, "T")
	return out
}

func segTypeName(t elf.ProgType) string {
	switch t {
	case elf.PT_NULL:
		return "NULL"
	case elf.PT_LOAD:
		return "LOAD"
	case elf.PT_DYNAMIC:
		return "DYNAMIC"
	case elf.PT_INTERP:
		return "INTERP"
	case elf.PT_NOTE:
		return "NOTE"
	case elf.PT_PHDR:
		return "PHDR"
	case elf.PT_TLS:
		return "TLS"
	case elf.PT_GNU_EH_FRAME:
		return "GNU_EH_FRAME"
	case elf.PT_GNU_STACK:
		return "GNU_STACK"
	case elf.PT_GNU_RELRO:
		return "GNU_RELRO"
	default:
		return fmt.Sprintf("0x%x", uint32(t))
	}
}

func symKind(s elf.Symbol) string {
	switch elf.SymType(s.Info & 0xf) {
	case elf.STT_FUNC:
		return "func"
	case elf.STT_OBJECT:
		return "object"
	case elf.STT_FILE:
		return "file"
	case elf.STT_SECTION:
		return "section"
	case elf.STT_TLS:
		return "tls"
	default:
		return "other"
	}
}

func mapSymbols(syms []elf.Symbol) []Symbol {
	out := make([]Symbol, 0, len(syms))
	for _, s := range syms {
		if s.Name == "" && s.Value == 0 {
			continue // null padding rows
		}
		scope := "local"
		switch elf.ST_BIND(s.Info) {
		case elf.STB_GLOBAL:
			scope = "global"
		case elf.STB_WEAK:
			scope = "weak"
		}
		out = append(out, Symbol{
			Name:    stripSymVersion(s.Name),
			Value:   s.Value,
			Size:    s.Size,
			Kind:    symKind(s),
			Scope:   scope,
			Defined: s.Section != elf.SHN_UNDEF,
		})
	}
	return out
}

func stripSymVersion(name string) string {
	base, _ := splitVersion(name)
	return base
}

// symNamesFor resolves the symbol-name table a relocation section links to
// (sec.Link -> SHT_SYMTAB or SHT_DYNSYM).
func symNamesFor(f *elf.File, sec *elf.Section) []string {
	if int(sec.Link) >= len(f.Sections) {
		return nil
	}
	switch f.Sections[sec.Link].Type {
	case elf.SHT_DYNSYM:
		syms, err := f.DynamicSymbols()
		if err != nil {
			return nil
		}
		return symbolNames(syms)
	case elf.SHT_SYMTAB:
		syms, err := f.Symbols()
		if err != nil {
			return nil
		}
		return symbolNames(syms)
	default:
		return nil
	}
}

func symbolNames(syms []elf.Symbol) []string {
	out := make([]string, len(syms))
	for i, s := range syms {
		out[i] = stripSymVersion(s.Name)
	}
	return out
}

// decodeRelocations parses SHT_RELA/SHT_REL entries (ELF32 + ELF64, either
// endianness). debug/elf exposes the entry layout only as documentation, so
// the record walk is implemented here.
func decodeRelocations(f *elf.File, sec *elf.Section, data []byte) ([]Reloc, error) {
	names := symNamesFor(f, sec)
	is64 := f.FileHeader.Class == elf.ELFCLASS64
	entrySz := 16 // RELA64: off8 info8 addend8 ; RELA32: 12 ; REL64: 16 ; REL32: 8
	if !is64 {
		entrySz = 12
	}
	if sec.Type == elf.SHT_REL {
		if is64 {
			entrySz = 16
		} else {
			entrySz = 8
		}
	}
	bo := binary.ByteOrder(binary.LittleEndian)
	if f.ByteOrder.String() != "LittleEndian" {
		bo = binary.BigEndian
	}
	var out []Reloc
	for off := 0; off+entrySz <= len(data); off += entrySz {
		var r Reloc
		var info uint64
		if is64 {
			r.Offset = bo.Uint64(data[off:])
			info = bo.Uint64(data[off+8:])
		} else if sec.Type == elf.SHT_RELA {
			r.Offset = uint64(bo.Uint32(data[off:]))
			info = uint64(bo.Uint32(data[off+4:]))
		} else {
			r.Offset = uint64(bo.Uint32(data[off:]))
			info = uint64(bo.Uint32(data[off+4:]))
		}
		var symIdx, rtype uint64
		if is64 {
			symIdx, rtype = info>>32, info&0xffffffff
		} else {
			symIdx, rtype = uint64(info>>8), uint64(info&0xff)
		}
		if symIdx > 0 && int(symIdx-1) < len(names) {
			r.Symbol = names[symIdx-1]
		}
		r.Type = fmt.Sprintf("%d", rtype)
		out = append(out, r)
	}
	return out, nil
}
