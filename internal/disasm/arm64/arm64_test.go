package arm64

import (
	"testing"

	"github.com/QYVORA/qyvora-aksum/internal/disasm"
)

func enc(words ...uint32) []byte {
	b := make([]byte, 0, 4*len(words))
	for _, w := range words {
		b = append(b, byte(w), byte(w>>8), byte(w>>16), byte(w>>24))
	}
	return b
}

func TestDecodeBasicFlows(t *testing.T) {
	d := New()
	// nop (0xd5033f5f) ; ret (0xd65f03c0)
	insts, err := d.Decode(enc(0xd5033f5f, 0xd65f03c0), 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(insts) != 2 {
		t.Fatalf("want 2 instructions, got %d", len(insts))
	}
	if insts[0].Flow != disasm.FlowNormal {
		t.Fatalf("nop should be FlowNormal: %+v", insts[0])
	}
	if insts[1].Flow != disasm.FlowRet {
		t.Fatalf("ret should be FlowRet: %+v", insts[1])
	}
}

func TestDecodeBLDirectCall(t *testing.T) {
	d := New()
	// BL .+0x3c: imm26 field at bits[25:0], displacement = imm26<<2, so
	// imm26 = 0x3c>>2 = 0x0f. (0x94000000 | 0x0f)
	insts, err := d.Decode(enc(0x94000000|0x0f), 0x2000)
	if err != nil {
		t.Fatal(err)
	}
	c := insts[0]
	if c.Flow != disasm.FlowCall {
		t.Fatalf("BL should be FlowCall: %+v", c)
	}
	if !c.HasTarget || c.Target != 0x2000+0x3c {
		t.Fatalf("BL target = %#x, want %#x", c.Target, 0x203c)
	}
}

func TestDecodeBConditional(t *testing.T) {
	d := New()
	// B.EQ .+0x3c (0x54000000 | (0x0f<<5)) -> conditional branch.
	insts, err := d.Decode(enc(0x54000000|(0x0f<<5)), 0x3000)
	if err != nil {
		t.Fatal(err)
	}
	c := insts[0]
	if c.Flow != disasm.FlowCond {
		t.Fatalf("B.EQ should be FlowCond: %+v", c)
	}
	if !c.HasTarget || c.Target != 0x3000+0x3c {
		t.Fatalf("B.EQ target = %#x, want %#x", c.Target, 0x303c)
	}
}

func TestDecodeUnconditionalB(t *testing.T) {
	d := New()
	// B .+0x4: imm26 = 0x4>>2 = 1. (0x14000000 | 0x01)
	insts, err := d.Decode(enc(0x14000000|0x01), 0x4000)
	if err != nil {
		t.Fatal(err)
	}
	c := insts[0]
	if c.Flow != disasm.FlowJmp {
		t.Fatalf("unconditional B should be FlowJmp: %+v", c)
	}
	if !c.HasTarget || c.Target != 0x4000+0x4 {
		t.Fatalf("B target = %#x, want %#x", c.Target, 0x4004)
	}
}

func TestDecodeCBZ(t *testing.T) {
	d := New()
	// CBZ X0, .+0x10 (0xb4000000 | (4<<5))
	insts, err := d.Decode(enc(0xb4000000|(4<<5)), 0x5000)
	if err != nil {
		t.Fatal(err)
	}
	c := insts[0]
	if c.Flow != disasm.FlowCond {
		t.Fatalf("CBZ should be FlowCond: %+v", c)
	}
	if !c.HasTarget || c.Target != 0x5000+0x10 {
		t.Fatalf("CBZ target = %#x, want %#x", c.Target, 0x5010)
	}
	if len(c.Operands) < 2 || c.Operands[0].Kind != "reg" {
		t.Fatalf("CBZ operand rendering wrong: %+v", c.Operands)
	}
}

func TestDecodeBadWord(t *testing.T) {
	d := New()
	// A word the decoder rejects (0x00000001) -> single 4-byte "<bad>".
	insts, err := d.Decode(enc(0x00000001, 0xd65f03c0), 0x6000)
	if err != nil {
		t.Fatal(err)
	}
	if len(insts) != 2 {
		t.Fatalf("want 2 instructions, got %d", len(insts))
	}
	if insts[0].Mnemonic != "<bad>" || insts[0].Size != 4 {
		t.Fatalf("bad word decode wrong: %+v", insts[0])
	}
	if insts[1].Flow != disasm.FlowRet {
		t.Fatalf("following instruction should still decode: %+v", insts[1])
	}
}

func TestArch(t *testing.T) {
	if New().Arch() != "AArch64" {
		t.Fatal("unexpected arch name")
	}
}
