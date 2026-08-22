package dataflow

import (
	"testing"

	strscan "github.com/QYVORA/qyvora-aksum/internal/analysis/strings"
	"github.com/QYVORA/qyvora-aksum/internal/analysis/structure"
	"github.com/QYVORA/qyvora-aksum/internal/disasm"
	"github.com/QYVORA/qyvora-aksum/internal/disasm/x86"
	"github.com/QYVORA/qyvora-aksum/internal/functions"
)

// hand-assembled x86-64 snippets (no assembler dependency).
const (
	codeBase = 0x401000
	gotSlot  = 0x3ff800 // fake GOT entry for strcpy
)

// caller: endbr64; lea rdi,[rip+0xff5 → 0x402000]; mov esi,5; call stub; ret
var callerCode = []byte{
	0xF3, 0x0F, 0x1E, 0xFA, // endbr64
	0x48, 0x8D, 0x3D, 0xF5, 0x0F, 0x00, 0x00, // lea rdi,[rip+0xff5] -> 0x402000
	0xBE, 0x05, 0x00, 0x00, 0x00, // mov esi,5
	0xE8, 0x01, 0x00, 0x00, 0x00, // call +1 -> 0x401016 (stub)
	0xC3, // ret
}

// stub (.plt): bnd jmp qword [rip+disp → gotSlot]
var stubCode = []byte{
	0xF2, 0xFF, 0x25, 0xE3, 0xE7, 0xFF, 0xFF, // bnd jmp [rip-0x181d] -> GOT 0x3ff800
	0xCC, // padding so rip-rel math is exercised over real sizes
}

func mustDecode(t *testing.T, code []byte, base uint64) []disasm.Instruction {
	t.Helper()
	insts, err := x86.New64().Decode(code, base)
	if err != nil {
		t.Fatalf("decode at %#x: %v", base, err)
	}
	return insts
}

func testFuncs(t *testing.T) ([]*functions.Function, uint64) {
	t.Helper()
	caller := &functions.Function{
		Name: "main", Address: codeBase, Size: len(callerCode),
		End:          codeBase + uint64(len(callerCode)),
		Confidence:   functions.ConfHigh,
		Instructions: mustDecode(t, callerCode, codeBase),
	}
	stubAddr := codeBase + uint64(len(callerCode)) // 0x40101f
	stub := &functions.Function{
		Name:         "plt_" + fmtHex(stubAddr),
		Address:      stubAddr,
		Size:         len(stubCode),
		End:          stubAddr + uint64(len(stubCode)),
		Confidence:   functions.ConfMedium,
		Sources:      []string{"PLT stub"},
		PLT:          true,
		Instructions: mustDecode(t, stubCode, stubAddr),
	}
	return []*functions.Function{caller, stub}, stubAddr
}

func fmtHex(v uint64) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 12)
	for v > 0 {
		out = append([]byte{digits[v&0xf]}, out...)
		v >>= 4
	}
	return string(out)
}

func TestCallSiteResolvesImportAndStringArg(t *testing.T) {
	funcs, _ := testFuncs(t)
	relocs := []structure.Reloc{{Offset: gotSlot, Type: "7", Symbol: "strcpy@GLIBC_2.14"}}
	strs := []strscan.Classified{{Str: strscan.Str{Value: "/tmp/pwn", Address: 0x402000}}}

	e := New(relocs, funcs, strs)
	sites := e.AnalyzeAll(funcs)

	var found *CallSite
	for i := range sites {
		if sites[i].Callee == "strcpy" {
			found = &sites[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no strcpy call site resolved; got %+v", sites)
	}
	if !found.ViaPLT {
		t.Errorf("ViaPLT = false, want true")
	}
	if len(found.Args) != 2 {
		t.Fatalf("args = %+v, want 2 resolved", found.Args)
	}
	rdi, rsi := found.Args[0], found.Args[1]
	if rdi.Register != "rdi" || rdi.Position != 0 || rdi.Kind != KindString ||
		rdi.Address != 0x402000 || rdi.Text != "/tmp/pwn" {
		t.Errorf("rdi arg = %+v", rdi)
	}
	if rsi.Kind != KindConstant || rsi.Value != 5 {
		t.Errorf("rsi arg = %+v", rsi)
	}
}

func TestStateResetsAtUnconditionalJump(t *testing.T) {
	// endbr64; lea rdi,[rip+...]; jmp over; nop (skipped); xor eax,eax;
	// call sub_..; ret — the tracked rdi must not survive the jump.
	code := []byte{
		0xF3, 0x0F, 0x1E, 0xFA, // endbr64
		0x48, 0x8D, 0x3D, 0x0F, 0x00, 0x00, 0x00, // lea rdi,[rip+15]
		0xEB, 0x02, // jmp +2 (skip the nop)
		0x90,       // nop (skipped by the jmp)
		0x31, 0xC0, // xor eax,eax
		0xE8, 0x01, 0x00, 0x00, 0x00, // call +1 -> sub
		0xC3, // ret
	}
	f := &functions.Function{
		Name: "jumpy", Address: 0x1000, Size: len(code), End: 0x1000 + uint64(len(code)),
		Instructions: mustDecode(t, code, 0x1000),
	}
	e := New(nil, []*functions.Function{f}, nil)
	sites := e.Analyze(f)
	if len(sites) != 1 {
		t.Fatalf("sites = %d, want 1", len(sites))
	}
	if len(sites[0].Args) != 0 {
		t.Errorf("tracked value survived unconditional jump reset: %+v", sites[0].Args)
	}
}

func TestXorSelfZeroesRegister(t *testing.T) {
	code := []byte{
		0x48, 0x31, 0xFF, // xor rdi,rdi
		0xE8, 0x01, 0x00, 0x00, 0x00, // call +1
		0xC3,
	}
	f := &functions.Function{
		Name: "z", Address: 0x2000, Size: len(code), End: 0x2000 + uint64(len(code)),
		Instructions: mustDecode(t, code, 0x2000),
	}
	e := New(nil, []*functions.Function{f}, nil)
	sites := e.Analyze(f)
	if len(sites) != 1 || len(sites[0].Args) != 1 {
		t.Fatalf("unexpected sites: %+v", sites)
	}
	arg := sites[0].Args[0]
	if arg.Kind != KindConstant || arg.Value != 0 {
		t.Errorf("arg = %+v, want zero constant", arg)
	}
}

func TestNoSpeculationWithoutTracking(t *testing.T) {
	code := []byte{0xC3} // bare ret: nothing resolvable
	f := &functions.Function{Name: "empty", Address: 0x10, End: 0x11,
		Instructions: mustDecode(t, code, 0x10)}
	e := New(nil, nil, nil)
	if sites := e.Analyze(f); len(sites) != 0 {
		t.Errorf("expected zero sites, got %+v", sites)
	}
}
