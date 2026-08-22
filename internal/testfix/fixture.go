// Package testfix crafts deterministic minimal ELF binaries in memory for
// tests. Every byte is a pure function of the requested variant — no
// checked-in blobs, no platform dependence, stable SHA-256 across runs and
// machines.
package testfix

import (
	"bytes"
	"encoding/binary"
)

// progHdr is one program-header record in the crafted image.
type progHdr struct {
	typ, flags           uint32
	off, vaddr, paddr    uint64
	filesz, memsz, align uint64
}

// Variant selects which fixture to craft.
type Variant int

const (
	// ExecNX is ET_EXEC with PT_GNU_STACK (RW) — PIE disabled, NX enabled,
	// RELRO none. Code: endbr64; xor eax,eax; ret.
	ExecNX Variant = iota
	// SharedPIE is ET_DYN with the same layout — exercises the DYN path
	// (PIE unknown without interpreter).
	SharedPIE
	// ExecNoStack omits PT_GNU_STACK entirely — NX must report disabled
	// (the historical default), exercising the negative property path.
	ExecNoStack
)

const (
	ehsize    = 64
	phentsize = 56
	shentsize = 64
)

// ELF64 crafts the fixture bytes for the variant.
func ELF64(v Variant) []byte {
	var code = []byte{
		0xF3, 0x0F, 0x1E, 0xFA, // endbr64
		0x31, 0xC0, // xor eax,eax
		0xC3, // ret
	}

	var progs []progHdr
	progs = append(progs, progHdr{
		typ: 1 /*PT_LOAD*/, flags: 5, /*R+X*/
		vaddr: 0x400000, paddr: 0x400000, filesz: uint64(len(code)), memsz: uint64(len(code)),
		align: 0x1000,
	})
	switch v {
	case ExecNX:
		progs = append(progs, progHdr{typ: 0x6474e551 /*PT_GNU_STACK*/, flags: 6 /*RW*/})
	case ExecNoStack:
		// nothing
	case SharedPIE:
		progs = append(progs, progHdr{typ: 0x6474e551, flags: 6})
	}

	shstrtab := buildShstrtab()
	phoff := ehsize
	dataOff := uint64(phoff + len(progs)*phentsize)
	shoff := dataOff + uint64(len(code))

	numSections := 3 // NULL + .text + .shstrtab
	total := shoff + uint64(numSections*shentsize) + uint64(len(shstrtab))

	buf := bytes.NewBuffer(make([]byte, 0, total))
	writeELFHeader(buf, v, shoff, uint16(len(progs)), uint16(numSections))
	mustWrite := func(v any) {
		if err := binary.Write(buf, binary.LittleEndian, v); err != nil {
			panic(err) // unreachable: in-memory buffer
		}
	}
	for _, p := range progs {
		mustWrite(p.typ)
		mustWrite(p.flags)
		if p.off == 0 && p.typ == 1 {
			mustWrite(dataOff)
		} else {
			mustWrite(uint64(0))
		}
		mustWrite(p.vaddr)
		mustWrite(p.paddr)
		mustWrite(p.filesz)
		mustWrite(p.memsz)
		mustWrite(p.align)
	}
	pad := int(dataOff) - buf.Len()
	buf.Write(bytes.Repeat([]byte{0xCC}, pad)) // gap filler between headers and code
	buf.Write(code)

	// Section headers: NULL, .text (covers code), .shstrtab.
	strOff := shoff + uint64(numSections*shentsize)
	textName := nameOffset(shstrtab, ".text")
	strName := nameOffset(shstrtab, ".shstrtab")
	writeSectionHeaders(buf, uint64(len(code)), dataOff, strOff, textName, strName, len(shstrtab))
	buf.Write(shstrtab)
	return buf.Bytes()
}

func writeELFHeader(buf *bytes.Buffer, v Variant, shoff uint64, phnum, shnum uint16) {
	mustWrite := func(v any) {
		if err := binary.Write(buf, binary.LittleEndian, v); err != nil {
			panic(err) // unreachable: in-memory buffer
		}
	}
	etype := uint16(2) // ET_EXEC
	if v == SharedPIE {
		etype = 3 // ET_DYN
	}
	buf.Write([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}) // magic, ELFCLASS64, LSB, EV_CURRENT, SYSV
	buf.Write(bytes.Repeat([]byte{0}, 8))              // padding
	mustWrite(etype)
	mustWrite(uint16(62))       // EM_X86_64
	mustWrite(uint32(1))        // e_version
	mustWrite(uint64(0x400000)) // e_entry
	mustWrite(uint64(ehsize))   // phoff
	mustWrite(shoff)            // shoff
	mustWrite(uint32(0))        // flags
	mustWrite(uint16(ehsize))   // ehsize
	mustWrite(uint16(phentsize))
	mustWrite(phnum)
	mustWrite(uint16(shentsize))
	mustWrite(shnum)
	mustWrite(uint16(2)) // shstrndx: .shstrtab
}

func writeSectionHeaders(buf *bytes.Buffer, textSize, textOff, strOff uint64, textName, strName uint32, strLen int) {
	// Elf64_Shdr is exactly 64 bytes: name/type (4+4), flags/addr/offset/
	// size (8 each), link/info (4+4), addralign/entsize (8 each).
	hdrs := []struct {
		name, typ              uint32
		flags, addr, off, size uint64
		link, info             uint32
		align, entsize         uint64
	}{
		{},
		{name: textName, typ: 1 /*SHT_PROGBITS*/, flags: 0x6, /*A|X*/
			addr: 0x400000, off: textOff, size: textSize, align: 16},
		{name: strName, typ: 3 /*SHT_STRTAB*/, off: strOff,
			size: uint64(strLen), align: 1},
	}
	mustWrite := func(v any) {
		if err := binary.Write(buf, binary.LittleEndian, v); err != nil {
			panic(err) // unreachable: in-memory buffer
		}
	}
	for _, h := range hdrs {
		mustWrite(h.name)
		mustWrite(h.typ)
		mustWrite(h.flags)
		mustWrite(h.addr)
		mustWrite(h.off)
		mustWrite(h.size)
		mustWrite(h.link)
		mustWrite(h.info)
		mustWrite(h.align)
		mustWrite(h.entsize)
	}
}

// buildShstrtab lays out "\0.text\0.shstrtab\0".
func buildShstrtab() []byte {
	out := []byte{0}
	out = append(out, ".text"...)
	out = append(out, 0)
	out = append(out, ".shstrtab"...)
	return append(out, 0)
}

func nameOffset(tab []byte, name string) uint32 {
	for i := range tab {
		if string(tab[i:i+len(name)]) == name && i+len(name) < len(tab) && tab[i+len(name)] == 0 {
			return uint32(i)
		}
	}
	return 0
}

// Corrupt flips one magic byte — exercises format-detection failure paths.
func Corrupt(data []byte) []byte {
	out := append([]byte(nil), data...)
	out[0] = 0x7e
	return out
}

// Truncate keeps only the first n bytes.
func Truncate(data []byte, n int) []byte {
	if n > len(data) {
		n = len(data)
	}
	return data[:n]
}
