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
	return buildELF(62 /*EM_X86_64*/, v, code)
}

// AArch64ELF crafts a minimal ELF64 declaring EM_AARCH64 whose .text holds
// real AArch64 machine code: an entry function that calls a helper via BL.
// Layout (all little-endian words):
//
//	0x400000: BL  0x400010   -> the entry function (call target seeding)
//	0x400004: MOV X0, #0
//	0x400008: RET
//	0x40000c: NOP            (padding)
//	0x400010: MOV X0, #1     -> the helper (reached as a call target)
//	0x400014: RET
func AArch64ELF() []byte {
	code := make([]byte, 0, 24)
	putA64 := func(w uint32) {
		code = append(code, byte(w), byte(w>>8), byte(w>>16), byte(w>>24))
	}
	putA64(0x94000004) // BL 0x400010: imm26 = 0x10>>2 = 4
	putA64(0xd2800000) // MOV X0, #0  (MOVZ X0, #0)
	putA64(0xd65f03c0) // RET
	putA64(0xd5033f5f) // NOP
	putA64(0xd2800020) // MOV X0, #1  (MOVZ X0, #1)
	putA64(0xd65f03c0) // RET
	return buildELF(183 /*EM_AARCH64*/, ExecNX, code)
}

// buildELF assembles the raw image from a machine id, a code string, a
// variant (drives program headers) and an entry address.
func buildELF(machine uint16, v Variant, code []byte) []byte {
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
	writeELFHeaderMachine(buf, v, machine, shoff, uint16(len(progs)), uint16(numSections))
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

func writeELFHeaderMachine(buf *bytes.Buffer, v Variant, machine uint16, shoff uint64, phnum, shnum uint16) {
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
	mustWrite(machine)
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

// PE32 crafts a minimal, structurally valid 32-bit PE image: DOS header +
// COFF header + PE32 optional header (16 data directories), a .text and an
// .idata section, and an import directory that resolves printf/exit from
// msvcrt.dll. It exercises identification, section enumeration, and import
// resolution on a non-ELF container.
//
// Layout (all offsets little-endian):
//
//	0x000 DOS header (e_lfanew = 0x80)
//	0x080 "PE\0\0" + COFF header
//	0x098 PE32 optional header (SizeOfOptionalHeader = 0xE0)
//	0x178 .text/.idata section headers (2 x 40 bytes)
//	0x200 .text raw
//	0x400 .idata raw (import descriptors + strings)
func PE32() []byte {
	const (
		peSigOff    = 0x80
		coffOff     = peSigOff + 4
		optHdrOff   = coffOff + 20
		optHdrSize  = 0xE0
		secTableOff = optHdrOff + optHdrSize
		textRawOff  = 0x200
		idataRawOff = 0x400
		textVA      = 0x1000
		idataVA     = 0x2000
		textChars   = 0x60000020 // CODE | EXECUTE | READ
		idataChars  = 0x40000040 // INITIALIZED_DATA | READ
		entryRVA    = textVA
		imageBase   = 0x400000
		numSections = 2
		numDataDirs = 16
	)
	idataSize := 0x200
	// RVA helper: relocation within .idata.
	rvaIn := func(rawOff int) uint32 { return idataVA + uint32(rawOff-idataRawOff) }

	size := idataRawOff + idataSize
	buf := make([]byte, size)

	w16 := func(off int, v uint16) { binary.LittleEndian.PutUint16(buf[off:], v) }
	w32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(buf[off:], v) }

	// DOS header.
	buf[0] = 'M'
	buf[1] = 'Z'
	w32(0x3C, peSigOff)

	// PE signature + COFF header.
	copy(buf[peSigOff:], "PE\x00\x00")
	w16(coffOff, 0x014c)        // Machine: i386
	w16(coffOff+2, numSections) // NumberOfSections
	w32(coffOff+4, 0x12345678)  // TimeDateStamp (deliberately non-zero)
	w32(coffOff+16, optHdrSize) // SizeOfOptionalHeader
	w16(coffOff+18, 0x0102)     // Characteristics: EXECUTABLE | 32BIT_MACHINE

	// PE32 optional header.
	w16(optHdrOff, 0x10b)       // Magic: PE32
	w32(optHdrOff+16, entryRVA) // AddressOfEntryPoint
	w32(optHdrOff+28, imageBase)
	w32(optHdrOff+36, 0x1000) // SectionAlignment (unused by parser)
	w32(optHdrOff+40, 0x200)  // FileAlignment
	w16(optHdrOff+68, 3)      // Subsystem: CONSOLE
	w32(optHdrOff+92, numDataDirs)
	// Data directory[1] = Import table.
	w32(optHdrOff+96+8, rvaIn(idataRawOff))
	w32(optHdrOff+96+8+4, uint32(idataSize))

	// Section headers.
	sec := func(base, chars uint32, name string, va, vsize, roff, rsize uint32) {
		copy(buf[base:], []byte(name))
		w32(int(base)+8, vsize)
		w32(int(base)+12, va)
		w32(int(base)+16, rsize)
		w32(int(base)+20, roff)
		w32(int(base)+36, chars)
	}
	sec(secTableOff, textChars, ".text", textVA, 0x200, textRawOff, 0x200)
	sec(secTableOff+40, idataChars, ".idata", idataVA, uint32(idataSize), idataRawOff, uint32(idataSize))

	// .idata raw: import descriptors (2 + terminator), ILT, IAT, names.
	d := idataRawOff
	w32(d, rvaIn(d+0x20))    // desc0.OriginalFirstThunk -> ILT at raw 0x420
	w32(d+12, rvaIn(d+0x78)) // desc0.Name -> "msvcrt.dll" at raw 0x478
	w32(d+16, rvaIn(d+0x40)) // desc0.FirstThunk -> IAT at raw 0x440
	// desc1 (raw 0x414) and desc2 (raw 0x422) stay zero -> terminator.
	// ILT at raw 0x420.
	w32(d+0x20, rvaIn(d+0x2C)) // thunk0 -> "printf" name at raw 0x42C
	w32(d+0x24, rvaIn(d+0x38)) // thunk1 -> "exit"   name at raw 0x438
	w32(d+0x28, 0)             // terminator
	// IAT at raw 0x440.
	w32(d+0x40, rvaIn(d+0x2C))
	w32(d+0x44, rvaIn(d+0x38))
	w32(d+0x48, 0)
	// Imported names (hint + NUL-terminated).
	copy(buf[d+0x2C+2:], "printf\x00")
	copy(buf[d+0x38+2:], "exit\x00")
	copy(buf[d+0x78:], "msvcrt.dll\x00")

	return buf
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
