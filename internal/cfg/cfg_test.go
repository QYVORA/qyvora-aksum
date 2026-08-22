package cfg

import (
	"testing"

	"github.com/QYVORA/qyvora-aksum/internal/disasm"
)

func mk(addr uint64, size int, flow disasm.FlowClass, target uint64, hasTarget bool) disasm.Instruction {
	return disasm.Instruction{Addr: addr, Size: size, Mnemonic: "x", Flow: flow, Target: target, HasTarget: hasTarget}
}

func TestStraightLineSingleBlock(t *testing.T) {
	insts := []disasm.Instruction{
		mk(0x100, 1, disasm.FlowNormal, 0, false),
		mk(0x101, 1, disasm.FlowNormal, 0, false),
		mk(0x102, 1, disasm.FlowRet, 0, false),
	}
	g := Build(0x100, insts)
	if g.Metrics().Blocks != 1 {
		t.Fatalf("straight-line code = 1 block, got %d", g.Metrics().Blocks)
	}
	if g.Metrics().Edges != 0 {
		t.Fatalf("ret terminates; want 0 edges got %d", g.Metrics().Edges)
	}
}

func TestConditionalSplitsAndEdges(t *testing.T) {
	insts := []disasm.Instruction{
		mk(0x100, 2, disasm.FlowCond, 0x110, true), // jcc -> 0x110
		mk(0x102, 1, disasm.FlowNormal, 0, false),  // fallthrough
		mk(0x103, 1, disasm.FlowRet, 0, false),
		mk(0x110, 1, disasm.FlowRet, 0, false),
	}
	g := Build(0x100, insts)
	m := g.Metrics()
	if m.Blocks != 3 {
		t.Fatalf("want 3 blocks (head/fallthrough/target), got %d", m.Blocks)
	}
	if m.Edges != 2 {
		t.Fatalf("cond emits branch + fallthrough edges, got %d", m.Edges)
	}
}

func TestUnconditionalJumpNoFallthrough(t *testing.T) {
	insts := []disasm.Instruction{
		mk(0x100, 2, disasm.FlowJmp, 0x104, true),
		mk(0x102, 1, disasm.FlowRet, 0, false), // skipped over
		mk(0x104, 1, disasm.FlowRet, 0, false),
	}
	g := Build(0x100, insts)
	if g.Metrics().Edges != 1 {
		t.Fatalf("jmp has exactly one successor, got %d", g.Metrics().Edges)
	}
	head := g.ByAddr[0x100]
	if len(head.Succs) != 1 || head.Succs[0] != 0x104 {
		t.Fatalf("jmp edge must land on target: %+v", head.Succs)
	}
}

func TestUnreachableBlockDetection(t *testing.T) {
	insts := []disasm.Instruction{
		mk(0x100, 1, disasm.FlowRet, 0, false),
		mk(0x101, 2, disasm.FlowJmp, 0x100, true), // dead code jumping back
	}
	g := Build(0x100, insts)
	if len(g.Unreachable) != 1 || g.Unreachable[0] != 0x101 {
		t.Fatalf("block after ret must be unreachable: %v", g.Unreachable)
	}
}

func TestBackEdgeCountsAsLoop(t *testing.T) {
	insts := []disasm.Instruction{
		mk(0x100, 2, disasm.FlowCond, 0x100, true), // self loop
		mk(0x102, 1, disasm.FlowRet, 0, false),
	}
	g := Build(0x100, insts)
	if g.Metrics().Loops == 0 {
		t.Fatal("self back-edge should count as a loop")
	}
}
