// Package arm64 implements the disasm.Decoder for AArch64 using
// golang.org/x/arch/arm64/arm64asm — a mature decoder rather than a
// hand-rolled one (spec section 45). Only the tested architecture is
// claimed: Decode refuses non-AArch64 machine types at the caller level.
//
// AArch64 is a fixed 4-byte instruction set, so linear sweep is reliable:
// every instruction is exactly 4 bytes and there is no length-desynchronizing
// variable-length encoding. Undecodable words still become a single 4-byte
// "<bad>" instruction so analysis continues past data/padding honestly.
package arm64

import (
	"fmt"

	"golang.org/x/arch/arm64/arm64asm"

	"github.com/QYVORA/qyvora-aksum/internal/disasm"
)

// Decoder implements disasm.Decoder for the AArch64 (ARM64 / ARMv8-A)
// instruction set.
type Decoder struct{}

// New returns an AArch64 decoder.
func New() *Decoder { return &Decoder{} }

// Arch reports the architecture handled.
func (d *Decoder) Arch() string { return "AArch64" }

// Decode walks the byte range linearly in 4-byte words. A word the decoder
// rejects becomes a 4-byte "<bad>" instruction so analysis can continue past
// data rather than aborting the region.
func (d *Decoder) Decode(code []byte, base uint64) ([]disasm.Instruction, error) {
	var out []disasm.Instruction
	for off := 0; off+4 <= len(code); off += 4 {
		inst, err := arm64asm.Decode(code[off : off+4])
		if err != nil {
			out = append(out, disasm.Instruction{
				Addr:     base + uint64(off),
				Size:     4,
				Bytes:    append([]byte(nil), code[off:off+4]...),
				Mnemonic: "<bad>",
				Flow:     disasm.FlowUnkn,
			})
			continue
		}
		out = append(out, convert(inst, base+uint64(off)))
	}
	return out, nil
}

func convert(inst arm64asm.Inst, addr uint64) disasm.Instruction {
	di := disasm.Instruction{
		Addr:     addr,
		Size:     4,
		Bytes:    []byte{byte(inst.Enc), byte(inst.Enc >> 8), byte(inst.Enc >> 16), byte(inst.Enc >> 24)},
		Mnemonic: inst.Op.String(),
		Flow:     classify(inst),
	}
	for _, a := range inst.Args {
		if a == nil {
			break
		}
		di.Operands = append(di.Operands, renderArg(a))
	}
	// Direct PC-relative targets are resolved from the arm64asm PCRel offset,
	// which is expressed relative to the branch instruction itself, plus the
	// implicit PC. B/BL carry it as the sole argument; CBZ/CBNZ at index 1;
	// TBZ/TBNZ at index 2.
	if pcRel := branchTarget(inst); pcRel != nil {
		di.Target = addr + uint64(*pcRel)
		di.HasTarget = true
	}
	return di
}

// branchTarget returns the PC-relative displacement of a direct branch, or
// nil when the instruction is not a direct branch (indirect BR/BLR, etc.).
func branchTarget(inst arm64asm.Inst) *int64 {
	op := inst.Op
	if op == arm64asm.B || op == arm64asm.BL {
		// B <target> and BL <target>. A conditional B carries a Cond arg and
		// the PCRel displacement follows it; an unconditional B has the
		// displacement as its only argument.
		for _, a := range inst.Args {
			if a == nil {
				break
			}
			if p, ok := a.(arm64asm.PCRel); ok {
				v := int64(p)
				return &v
			}
		}
	}
	if op == arm64asm.CBZ || op == arm64asm.CBNZ {
		for _, a := range inst.Args {
			if p, ok := a.(arm64asm.PCRel); ok {
				v := int64(p)
				return &v
			}
		}
	}
	if op == arm64asm.TBZ || op == arm64asm.TBNZ {
		for _, a := range inst.Args {
			if p, ok := a.(arm64asm.PCRel); ok {
				v := int64(p)
				return &v
			}
		}
	}
	return nil
}

func classify(inst arm64asm.Inst) disasm.FlowClass {
	switch inst.Op {
	case arm64asm.BL:
		return disasm.FlowCall
	case arm64asm.B:
		// An unconditional B has no Cond arg; a condition-suffixed branch
		// (B.EQ etc.) carries a Cond argument.
		for _, a := range inst.Args {
			if _, ok := a.(arm64asm.Cond); ok {
				return disasm.FlowCond
			}
		}
		return disasm.FlowJmp
	case arm64asm.CBZ, arm64asm.CBNZ, arm64asm.TBZ, arm64asm.TBNZ:
		return disasm.FlowCond
	case arm64asm.RET, arm64asm.ERET:
		return disasm.FlowRet
	case arm64asm.BR, arm64asm.BLR:
		return disasm.FlowJmp
	case arm64asm.BRK, arm64asm.HLT:
		return disasm.FlowHlt
	case arm64asm.SVC:
		// Supervisor call-handles like a system call; mark it a call-like
		// terminal for reachability purposes.
		return disasm.FlowCall
	default:
		return disasm.FlowNormal
	}
}

func renderArg(a arm64asm.Arg) disasm.Operand {
	switch v := a.(type) {
	case arm64asm.Reg:
		return disasm.Operand{Text: v.String(), Kind: "reg"}
	case arm64asm.RegSP:
		return disasm.Operand{Text: v.String(), Kind: "reg"}
	case arm64asm.PCRel:
		return disasm.Operand{Text: fmt.Sprintf("pc%+#x", int64(v)), Kind: "imm", Value: uint64(int64(v))}
	case arm64asm.Imm:
		return disasm.Operand{Text: fmt.Sprintf("%#x", v.Imm), Kind: "imm", Value: uint64(v.Imm)}
	case arm64asm.Imm64:
		return disasm.Operand{Text: fmt.Sprintf("%#x", v.Imm), Kind: "imm", Value: v.Imm}
	case arm64asm.MemImmediate:
		return disasm.Operand{Text: "[" + v.Base.String() + "] ", Kind: "mem"}
	case arm64asm.Cond:
		return disasm.Operand{Text: v.String(), Kind: "cond"}
	default:
		return disasm.Operand{Text: a.String(), Kind: "other"}
	}
}
