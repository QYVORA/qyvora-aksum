// Package structure enumerates the ELF's structural views: sections,
// segments, symbols (static + dynamic), imports, and exports. Everything is
// derived from the parsed file; nothing is guessed.
package structure

import (
	"strings"

	"debug/elf"
	"fmt"
	"io"

	"github.com/QYVORA/qyvora-aksum/internal/binary"
	"github.com/QYVORA/qyvora-aksum/internal/loader"
)

// Section is one entry of the section header table.
type Section struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Address   uint64   `json:"address"`
	Offset    uint64   `json:"offset"`
	Size      uint64   `json:"size"`
	Flags     []string `json:"flags,omitempty"`
	Alignment uint64   `json:"alignment"`
}

// Segment is one program-header entry.
type Segment struct {
	Type        string `json:"type"`
	Flags       string `json:"flags"` // rwx
	Offset      uint64 `json:"offset"`
	VirtualAddr uint64 `json:"vaddr"`
	FileSize    uint64 `json:"filesz"`
	MemSize     uint64 `json:"memsz"`
	Alignment   uint64 `json:"align"`
}

// Symbol is one symbol-table entry.
type Symbol struct {
	Name    string `json:"name"`
	Value   uint64 `json:"value"`
	Size    uint64 `json:"size"`
	Kind    string `json:"kind"`  // func | object | other
	Scope   string `json:"scope"` // global | local | weak
	Defined bool   `json:"defined"`
}

// Import is one imported (undefined, dynamically bound) symbol.
type Import struct {
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	FromNeeded   string `json:"from_library,omitempty"`
	Unclassified bool   `json:"-"`
}

// Export is one exported dynamic symbol.
type Export struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
	Size  uint64 `json:"size"`
	Kind  string `json:"kind"`
}

// Reloc is one relocation entry.
type Reloc struct {
	Offset uint64 `json:"offset"`
	Type   string `json:"type"`
	Symbol string `json:"symbol,omitempty"`
}

// Image bundles the file handle with its identified Target for the
// structural commands.
type Image struct {
	Target *binary.Target
	file   *elf.File
}

// Open parses path as an executable image. It refuses files that are not
// ELF with a clear unsupported error.
func Open(path string) (*Image, error) {
	t, err := loader.Open(path)
	if err != nil {
		return nil, err
	}
	if t.Format != binary.FormatELF {
		return nil, fmt.Errorf("%s: structural analysis requires an ELF image; got format %q", path, t.Format)
	}
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("parse ELF %s: %w", path, err)
	}
	return &Image{Target: t, file: f}, nil
}

// Close releases the underlying file.
func (im *Image) Close() error { return im.file.Close() }

// Sections lists all sections in table order.
func (im *Image) Sections() []Section {
	out := make([]Section, 0, len(im.file.Sections))
	for _, s := range im.file.Sections {
		out = append(out, Section{
			Name:      s.Name,
			Type:      sectionTypeName(s.Type),
			Address:   s.Addr,
			Offset:    s.Offset,
			Size:      s.Size,
			Flags:     sectionFlagNames(s.Flags),
			Alignment: s.Addralign,
		})
	}
	return out
}

// Segments lists all program headers.
func (im *Image) Segments() []Segment {
	out := make([]Segment, 0, len(im.file.Progs))
	for _, p := range im.file.Progs {
		var fl strings.Builder
		if p.Flags&elf.PF_R != 0 {
			fl.WriteByte('r')
		} else {
			fl.WriteByte('-')
		}
		if p.Flags&elf.PF_W != 0 {
			fl.WriteByte('w')
		} else {
			fl.WriteByte('-')
		}
		if p.Flags&elf.PF_X != 0 {
			fl.WriteByte('x')
		} else {
			fl.WriteByte('-')
		}
		out = append(out, Segment{
			Type:        segTypeName(p.Type),
			Flags:       fl.String(),
			Offset:      p.Off,
			VirtualAddr: p.Vaddr,
			FileSize:    p.Filesz,
			MemSize:     p.Memsz,
			Alignment:   p.Align,
		})
	}
	return out
}

// Symbols returns static symbol-table entries; empty when stripped.
func (im *Image) Symbols() []Symbol {
	syms, err := im.file.Symbols()
	if err != nil {
		return nil
	}
	return mapSymbols(syms)
}

// DynamicSymbols returns .dynsym entries; empty when absent.
func (im *Image) DynamicSymbols() []Symbol {
	syms, err := im.file.DynamicSymbols()
	if err != nil {
		return nil
	}
	return mapSymbols(syms)
}

// Imports returns undefined dynamic symbols (what this binary needs from
// libraries). Version suffixes (@GLIBC_...) are split off for classification.
func (im *Image) Imports() []Import {
	syms, err := im.file.DynamicSymbols()
	if err != nil {
		return nil
	}
	var out []Import
	for _, s := range syms {
		if s.Section != elf.SHN_UNDEF || s.Name == "" {
			continue
		}
		name, version := splitVersion(s.Name)
		out = append(out, Import{Name: name, Version: version})
	}
	return out
}

// Exports returns defined dynamic symbols visible to other objects.
func (im *Image) Exports() []Export {
	syms, err := im.file.DynamicSymbols()
	if err != nil {
		return nil
	}
	var out []Export
	for _, s := range syms {
		if s.Section == elf.SHN_UNDEF || s.Name == "" {
			continue
		}
		name, _ := splitVersion(s.Name)
		out = append(out, Export{
			Name:  name,
			Value: s.Value,
			Size:  s.Size,
			Kind:  symKind(s),
		})
	}
	return out
}

// Relocs returns relocation entries across all relocation sections.
func (im *Image) Relocs() []Reloc {
	var out []Reloc
	for _, s := range im.file.Sections {
		switch s.Type {
		case elf.SHT_RELA, elf.SHT_REL: //nolint:misspell // ELF spec term
			data, err := s.Data()
			if err != nil {
				continue
			}
			rels, err := decodeRelocations(im.file, s, data)
			if err != nil {
				continue
			}
			out = append(out, rels...)
		}
	}
	return out
}

// ReadCode returns raw bytes at virtual address addr (length n) using the
// section that contains it, or via program headers when no section matches
// (stripped/odd layouts).
func (im *Image) ReadCode(addr uint64, n int) ([]byte, error) {
	for _, s := range im.file.Sections {
		if s.Type != elf.SHT_NOBITS && addr >= s.Addr && addr < s.Addr+s.Size {
			data := make([]byte, n)
			read, err := s.ReadAt(data, int64(addr-s.Addr))
			if err != nil && err != io.EOF {
				return nil, err
			}
			return data[:read], nil
		}
	}
	for _, p := range im.file.Progs {
		if p.Type == elf.PT_LOAD && addr >= p.Vaddr && addr < p.Vaddr+p.Memsz {
			data := make([]byte, n)
			read, err := p.ReadAt(data, int64(addr-p.Vaddr))
			if err != nil && err != io.EOF {
				return nil, err
			}
			return data[:read], nil
		}
	}
	return nil, fmt.Errorf("address %#x not mapped by any readable region", addr)
}

// ExecSections exposes the raw elf.File for analysis stages needing deeper
// access while keeping a single parse of the file.
func (im *Image) ExecSections() []*elf.Section { return im.file.Sections }

// RawFile exposes the parsed file to trusted internal packages only.
func (im *Image) RawFile() *elf.File { return im.file }
