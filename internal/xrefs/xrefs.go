// Package xrefs builds cross-reference indexes: which instruction addresses
// reference which code targets and data addresses. Data references come from
// RIP-relative memory operands (the dominant x86-64 addressing form for
// globals/strings), giving the strings -> functions linkage the pipeline
// requires (spec section 60).
package xrefs

import (
	"sort"
	"strings"

	"github.com/QYVORA/qyvora-aksum/internal/disasm"
)

// Ref is one cross-reference record.
type Ref struct {
	From     uint64 `json:"from"`          // referencing instruction address
	FromFunc uint64 `json:"from_function"` // containing function address
	To       uint64 `json:"to"`            // referenced target
	Kind     string `json:"kind"`          // call | jump | data
}

// Table indexes references by target address.
type Table struct {
	ByTarget map[uint64][]Ref
}

// Build scans instructions (with their owning function addresses) and
// records call, jump, and rip-relative data references.
func Build(insts []disasm.Instruction, ownerOf map[uint64]uint64) *Table {
	t := &Table{ByTarget: map[uint64][]Ref{}}
	add := func(r Ref) { t.ByTarget[r.To] = append(t.ByTarget[r.To], r) }
	for i := range insts {
		in := &insts[i]
		owner := ownerOf[in.Addr]
		switch in.Flow {
		case disasm.FlowCall:
			if in.HasTarget {
				add(Ref{From: in.Addr, FromFunc: owner, To: in.Target, Kind: "call"})
			}
		case disasm.FlowJmp, disasm.FlowCond:
			if in.HasTarget {
				add(Ref{From: in.Addr, FromFunc: owner, To: in.Target, Kind: "jump"})
			}
		default:
			// RIP-relative data operand: effective address = next instruction
			// boundary + displacement. The decoder stores disp in mem operands.
			for _, op := range in.Operands {
				if op.Kind == "mem" && isRipRel(op.Text) {
					to := in.Addr + uint64(in.Size) + uint64(int64(op.Value))
					add(Ref{From: in.Addr, FromFunc: owner, To: to, Kind: "data"})
				}
			}
		}
	}
	return t
}

// XrefsTo returns sorted references landing on addr.
func (t *Table) XrefsTo(addr uint64) []Ref {
	out := append([]Ref(nil), t.ByTarget[addr]...)
	sort.Slice(out, func(i, j int) bool { return out[i].From < out[j].From })
	return out
}

// isRipRel detects Intel-syntax RIP-relative operands ("[RIP+0x1234]").
func isRipRel(opText string) bool {
	return len(opText) > 4 && strings.EqualFold(opText[:4], "[rip")
}
