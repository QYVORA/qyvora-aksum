// Package cfg constructs basic blocks and control-flow graphs from decoded
// instruction streams (spec sections 13, 17). Edges are only emitted when a
// target is actually resolved — no plausible-looking fake edges.
package cfg

import (
	"github.com/QYVORA/qyvora-aksum/internal/disasm"
)

// Block is one basic block: a straight-line instruction run ending at a
// control-flow transfer.
type Block struct {
	Start    uint64               `json:"start"`
	End      uint64               `json:"end"` // exclusive
	Instrs   []disasm.Instruction `json:"-"`
	Succs    []uint64             `json:"successors"`
	Preds    []uint64             `json:"predecessors"`
	Terminal string               `json:"terminal"` // flow class of last instruction
}

// Graph is the CFG of one function.
type Graph struct {
	Entry       uint64            `json:"entry"`
	Blocks      []*Block          `json:"-"`
	ByAddr      map[uint64]*Block `json:"-"`
	Edges       int               `json:"edges"`
	Loops       int               `json:"loops"` // back-edge count
	Unreachable []uint64          `json:"unreachable_blocks,omitempty"`
}

// Build splits an instruction list into basic blocks. Leaders are:
// the first instruction, branch targets, instructions following
// conditional/unconditional jumps, and instructions following returns/halts.
func Build(entry uint64, insts []disasm.Instruction) *Graph {
	g := &Graph{Entry: entry, ByAddr: map[uint64]*Block{}}
	if len(insts) == 0 {
		return g
	}

	leader := map[int]bool{0: true}
	targetIdx := map[uint64]int{}
	for i := range insts {
		targetIdx[insts[i].Addr] = i
	}
	for i := range insts {
		in := &insts[i]
		switch in.Flow {
		case disasm.FlowJmp, disasm.FlowCond:
			if in.HasTarget {
				if t, ok := targetIdx[in.Target]; ok {
					leader[t] = true
				}
			}
			// The instruction after any branch starts a new block: after a
			// conditional it is the fallthrough arm; after an unconditional
			// jump it is (usually) unreachable code.
			if i+1 < len(insts) {
				leader[i+1] = true
			}
		case disasm.FlowRet, disasm.FlowHlt:
			if i+1 < len(insts) {
				leader[i+1] = true
			}
		}
	}

	// Materialize blocks over leader runs.
	var order []*Block
	for i := 0; i < len(insts); {
		j := i + 1
		for j < len(insts) && !leader[j] {
			j++
		}
		b := &Block{
			Start:    insts[i].Addr,
			End:      insts[j-1].Addr + uint64(insts[j-1].Size),
			Instrs:   append([]disasm.Instruction(nil), insts[i:j]...),
			Terminal: insts[j-1].Flow.String(),
		}
		g.ByAddr[b.Start] = b
		order = append(order, b)
		i = j
	}

	// Wire edges.
	for bi, b := range order {
		last := &b.Instrs[len(b.Instrs)-1]
		addEdge := func(to uint64) {
			if tb, ok := g.ByAddr[to]; ok {
				b.Succs = append(b.Succs, to)
				tb.Preds = append(tb.Preds, b.Start)
				g.Edges++
			}
		}
		switch last.Flow {
		case disasm.FlowJmp:
			if last.HasTarget {
				addEdge(last.Target)
			} // unresolved indirect jmp: edge intentionally absent
		case disasm.FlowCond:
			if last.HasTarget {
				addEdge(last.Target)
			}
			if bi+1 < len(order) {
				addEdge(order[bi+1].Start)
			}
		case disasm.FlowRet, disasm.FlowHlt:
			// terminal; no successors
		default:
			if bi+1 < len(order) {
				addEdge(order[bi+1].Start)
			}
		}
	}

	// Loop detection via back edges (target <= block start on DFS order).
	for _, b := range order {
		for _, s := range b.Succs {
			if s <= b.Start {
				g.Loops++
			}
		}
	}

	// Unreachable blocks: no predecessors and not entry.
	for _, b := range order {
		if b.Start != g.Entry && len(b.Preds) == 0 {
			g.Unreachable = append(g.Unreachable, b.Start)
		}
	}
	return g
}

// Stats renders compact metrics used by reports and findings.
type Stats struct {
	Blocks      int `json:"blocks"`
	Edges       int `json:"edges"`
	Loops       int `json:"loops"`
	Unreachable int `json:"unreachable"`
}

// Metrics summarizes a graph.
func (g *Graph) Metrics() Stats {
	return Stats{
		Blocks:      len(g.ByAddr),
		Edges:       g.Edges,
		Loops:       g.Loops,
		Unreachable: len(g.Unreachable),
	}
}
