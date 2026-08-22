// Package disasm defines the architecture-neutral instruction model and
// decoder interface. The internal representation is structured (mnemonic,
// operands, control-flow class, referenced targets) so later stages —
// basic blocks, CFG, call graph, security checks — consume data, not text
// dumps (spec sections 11-12).
package disasm

import "fmt"

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
