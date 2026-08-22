package x86

import (
	"testing"

	"github.com/QYVORA/qyvora-aksum/internal/disasm"
)

func TestDecodeBasicFlows(t *testing.T) {
	d := New64()
	// push rbp; ret
	insts, err := d.Decode([]byte{0x55, 0xC3}, 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(insts) != 2 {
		t.Fatalf("want 2 instructions, got %d", len(insts))
	}
	if insts[0].Mnemonic != "PUSH" || insts[1].Flow != disasm.FlowRet {
		t.Fatalf("unexpected decode: %+v", insts)
	}
}

func TestDecodeEndbr64(t *testing.T) {
	d := New64()
	insts, err := d.Decode([]byte{0xF3, 0x0F, 0x1E, 0xFA, 0xC3}, 0x2000)
	if err != nil {
		t.Fatal(err)
	}
	if len(insts) != 2 {
		t.Fatalf("endbr64 must consume exactly 4 bytes; got %d instructions", len(insts))
	}
	if insts[0].Mnemonic != "ENDBR64" || insts[0].Size != 4 {
		t.Fatalf("bad endbr64 decode: %+v", insts[0])
	}
}

func TestDecodeCallTargetArithmetic(t *testing.T) {
	d := New64()
	// e8 05 00 00 00 = call +5 ; target = next_addr(0x3005) + 5 = 0x300a
	base := uint64(0x3000)
	insts, err := d.Decode([]byte{0xE8, 0x05, 0x00, 0x00, 0x00}, base)
	if err != nil {
		t.Fatal(err)
	}
	c := insts[0]
	if c.Flow != disasm.FlowCall || !c.HasTarget {
		t.Fatalf("expected resolved call, got %+v", c)
	}
	if c.Target != base+5+5 {
		t.Fatalf("call target = %#x, want %#x", c.Target, base+10)
	}
}

func TestDecodeConditionalJump(t *testing.T) {
	d := New64()
	// 74 FE = je -2 : self-loop back to same address
	base := uint64(0x4000)
	insts, err := d.Decode([]byte{0x74, 0xFE}, base)
	if err != nil {
		t.Fatal(err)
	}
	j := insts[0]
	if j.Flow != disasm.FlowCond {
		t.Fatalf("expected conditional, got %v", j.Flow)
	}
	if j.HasTarget && j.Target != base {
		t.Fatalf("self-loop target = %#x, want %#x", j.Target, base)
	}
}

func TestDecodeBadBytesContinue(t *testing.T) {
	d := New64()
	insts, err := d.Decode([]byte{0xFF, 0xFF, 0xFF, 0x90}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(insts) == 0 {
		t.Fatal("no instructions")
	}
	badCount := 0
	for _, in := range insts {
		if in.Mnemonic == "<bad>" && in.Size == 1 {
			badCount++
		}
	}
	if badCount == 0 {
		t.Fatalf("expected <bad> markers, got %+v", insts)
	}
}

func TestArchReporting(t *testing.T) {
	if New64().Arch() != "x86-64" || New32().Arch() != "x86" {
		t.Fatal("arch reporting broken")
	}
}
