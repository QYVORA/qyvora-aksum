// Package x86 implements the disasm.Decoder for x86/x86-64 using
// golang.org/x/arch/x86/x86asm — a mature decoder rather than a hand-rolled
// one (spec section 45). Only tested architectures are claimed: Decode
// refuses non-x86 machine types at the caller level.
package x86

import (
	"fmt"

	"golang.org/x/arch/x86/x86asm"

	"github.com/QYVORA/qyvora-aksum/internal/disasm"
)

// Decoder decodes 64-bit (default) or 32-bit x86.
type Decoder struct {
	bits int
}

// New64 returns an x86-64 decoder.
func New64() *Decoder { return &Decoder{bits: 64} }

// New32 returns an IA-32 decoder.
func New32() *Decoder { return &Decoder{bits: 32} }

// Arch reports the architecture handled.
func (d *Decoder) Arch() string {
	if d.bits == 64 {
		return "x86-64"
	}
	return "x86"
}

// Decode walks the byte range linearly. Invalid bytes become a single-byte
// "bad" instruction so analysis can continue past data/padding instead of
// aborting the whole region — linear sweep reality, reported honestly via
// the mnemonic "<bad>". CET endbr64/endbr32 are pre-decoded because the
// upstream decoder predates them; misreading their 4 bytes would desync
// every following instruction.
func (d *Decoder) Decode(code []byte, base uint64) ([]disasm.Instruction, error) {
	var out []disasm.Instruction
	mode := d.bits
	for off := 0; off < len(code); {
		if n, name := endbrAt(code[off:]); n > 0 {
			out = append(out, disasm.Instruction{
				Addr:     base + uint64(off),
				Size:     n,
				Bytes:    append([]byte(nil), code[off:off+n]...),
				Mnemonic: name,
				Flow:     disasm.FlowNormal,
			})
			off += n
			continue
		}
		inst, err := x86asm.Decode(code[off:], mode)
		n := inst.Len
		if err != nil || n == 0 || n > len(code)-off {
			out = append(out, disasm.Instruction{
				Addr:     base + uint64(off),
				Size:     1,
				Bytes:    []byte{code[off]},
				Mnemonic: "<bad>",
				Flow:     disasm.FlowUnkn,
			})
			off++
			continue
		}
		out = append(out, convert(inst, code[off:off+n], base+uint64(off)))
		off += n
	}
	return out, nil
}

// endbrAt recognizes CET terminator-inhibit instructions.
func endbrAt(b []byte) (int, string) {
	if len(b) >= 4 && b[0] == 0xF3 && b[1] == 0x0F && b[2] == 0x1E {
		switch b[3] {
		case 0xFA:
			return 4, "ENDBR64"
		case 0xFB:
			return 4, "ENDBR32"
		}
	}
	return 0, ""
}

func convert(inst x86asm.Inst, raw []byte, addr uint64) disasm.Instruction {
	di := disasm.Instruction{
		Addr:     addr,
		Size:     inst.Len,
		Bytes:    append([]byte(nil), raw...),
		Mnemonic: inst.Op.String(),
		Flow:     classify(inst.Op),
	}
	for _, arg := range []any{inst.Args[0], inst.Args[1], inst.Args[2]} {
		if arg == nil {
			break
		}
		di.Operands = append(di.Operands, renderArg(arg))
	}
	// Direct call/jmp targets: the sole immediate operand.
	switch di.Flow {
	case disasm.FlowCall, disasm.FlowJmp, disasm.FlowCond:
		args := nonNilArgs(inst)
		if len(args) == 1 {
			if imm, ok := args[0].(x86asm.Imm); ok {
				di.Target = uint64(int64(imm))
				di.HasTarget = true
			}
			if rel, ok := args[0].(x86asm.Rel); ok {
				di.Target = addr + uint64(int64(rel)) + uint64(inst.Len)
				di.HasTarget = true
			}
		}
	}
	return di
}

func nonNilArgs(inst x86asm.Inst) []x86asm.Arg {
	n := 0
	for _, a := range inst.Args {
		if a != nil {
			n++
		}
	}
	return inst.Args[:n]
}

func renderArg(arg any) disasm.Operand {
	switch a := arg.(type) {
	case x86asm.Reg:
		return disasm.Operand{Text: a.String(), Kind: "reg"}
	case x86asm.Imm:
		return disasm.Operand{Text: fmt.Sprintf("%#x", int64(a)), Kind: "imm", Value: uint64(int64(a))}
	case x86asm.Rel:
		return disasm.Operand{Text: fmt.Sprintf("%#x", int64(a)), Kind: "imm", Value: uint64(int64(a))}
	case x86asm.Mem:
		return disasm.Operand{Text: memText(a), Kind: "mem", Value: uint64(int64(a.Disp))}
	default:
		return disasm.Operand{Text: fmt.Sprint(arg), Kind: "other"}
	}
}

func memText(m x86asm.Mem) string {
	s := "["
	if m.Base != 0 {
		s += m.Base.String()
	}
	if m.Index != 0 {
		if m.Base != 0 {
			s += "+"
		}
		s += m.Index.String()
		if m.Scale > 1 {
			s += fmt.Sprintf("*%d", m.Scale)
		}
	}
	if m.Disp != 0 || (m.Base == 0 && m.Index == 0) {
		if s != "[" && m.Disp >= 0 {
			s += "+"
		}
		s += fmt.Sprintf("%#x", m.Disp)
	}
	return s + "]"
}

func classify(op x86asm.Op) disasm.FlowClass {
	switch op {
	case x86asm.CALL, x86asm.LCALL:
		return disasm.FlowCall
	case x86asm.JMP, x86asm.LJMP:
		return disasm.FlowJmp
	case x86asm.RET:
		return disasm.FlowRet
	case x86asm.HLT, x86asm.UD2, x86asm.INT:
		return disasm.FlowHlt
	default:
		name := op.String()
		// Jcc family (JE/JNE/JLE/...) plus loop instructions behave as
		// conditional branches for CFG purposes.
		if name == "JMP" || name == "LJMP" {
			return disasm.FlowJmp
		}
		if len(name) > 1 && (name[0] == 'J' || name == "LOOP" || name == "LOOPE" || name == "LOOPNE") &&
			name != "JMP" {
			return disasm.FlowCond
		}
		return disasm.FlowNormal
	}
}
