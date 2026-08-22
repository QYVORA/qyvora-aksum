// Package disasm defines the architecture-neutral instruction model and
// decoder interface. The internal representation is structured (mnemonic,
// operands, control-flow class, referenced targets) so later stages —
// basic blocks, CFG, call graph, security checks — consume data, not text
// dumps (spec sections 11-12).
package disasm

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// FlowClass describes how an instruction affects control flow.
type FlowClass int

const (
	FlowNormal FlowClass = iota
	FlowCall             // direct/near call: target is a function entry
	FlowJmp              // unconditional jump
	FlowCond             // conditional branch
	FlowRet
	FlowHlt // terminal: hlt, ud2, trap-like
	FlowUnkn
)

func (f FlowClass) String() string {
	switch f {
	case FlowCall:
		return "call"
	case FlowJmp:
		return "jmp"
	case FlowCond:
		return "cond"
	case FlowRet:
		return "ret"
	case FlowHlt:
		return "halt"
	default:
		return "normal"
	}
}

// Operand is one decoded operand.
type Operand struct {
	Text  string `json:"text"`  // human rendering, e.g. "rax", "[rbp-0x8]"
	Kind  string `json:"kind"`  // reg | imm | mem
	Value uint64 `json:"value"` // immediate value or memory displacement hint
}

// Instruction is one decoded machine instruction.
type Instruction struct {
	Addr      uint64    `json:"addr"`
	Size      int       `json:"size"`
	Bytes     []byte    `json:"bytes"`
	Mnemonic  string    `json:"mnemonic"`
	Operands  []Operand `json:"operands,omitempty"`
	Flow      FlowClass `json:"flow"`
	Target    uint64    `json:"target,omitempty"` // resolved direct target
	HasTarget bool      `json:"-"`
	SymTarget string    `json:"symbol_target,omitempty"` // symbol name when resolvable
}

// String renders "0x401240: call 0x401560 <foo>" style lines.
func (i Instruction) String() string {
	s := fmt.Sprintf("%#x: %s", i.Addr, i.Mnemonic)
	for _, op := range i.Operands {
		s += " " + op.Text
	}
	if i.HasTarget && i.Target != 0 {
		s += fmt.Sprintf(" -> %#x", i.Target)
	}
	if i.SymTarget != "" {
		s += " <" + i.SymTarget + ">"
	}
	return s
}

// Decoder decodes a linear region into instructions starting at base.
type Decoder interface {
	Decode(code []byte, base uint64) ([]Instruction, error)
	// Arch reports the architecture name this decoder handles.
	Arch() string
}

// reRipOperand matches the Intel rendering of a RIP-relative operand,
// e.g. "[RIP+0x1234]" / "[rip-0x8]". The renderer prints the raw disp32
// magnitude under a '+' even when the displacement is negative.
var reRipOperand = regexp.MustCompile(`(?i)^\[\s*rip\s*([+-])\s*(0x[0-9a-f]+|\d+)\s*(?:\].*)$`)

// IsRipRelative reports whether a memory operand is RIP-relative.
func IsRipRelative(op Operand) bool {
	return op.Kind == "mem" && len(op.Text) > 4 && strings.EqualFold(op.Text[:4], "[rip")
}

// ripDisplacement recovers the signed displacement for a RIP-relative
// operand. Operand.Value carries the unsigned magnitude (the upstream
// decoder zero-extends negative disp32 values), so the rendered sign and
// width decide polarity: '+0xffffxxxx' is a negative 32-bit displacement.
func ripDisplacement(op Operand) int64 {
	m := reRipOperand.FindStringSubmatch(op.Text)
	if m == nil {
		return int64(op.Value)
	}
	v, err := strconv.ParseUint(m[2], 0, 64)
	if err != nil {
		return int64(op.Value)
	}
	if m[1] == "-" {
		return -int64(v)
	}
	if v > math.MaxInt32 && v <= math.MaxUint32 {
		return int64(v) - (1 << 32)
	}
	return int64(v)
}

// RipTarget returns the effective address targeted by a RIP-relative
// memory operand of instruction in: next-instruction boundary plus the
// sign-corrected displacement.
func RipTarget(in Instruction, op Operand) uint64 {
	return in.Addr + uint64(in.Size) + uint64(ripDisplacement(op))
}
