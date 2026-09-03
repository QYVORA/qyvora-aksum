package pe

import (
	"bytes"
	"testing"

	"github.com/QYVORA/qyvora-aksum/internal/binary"
	"github.com/QYVORA/qyvora-aksum/internal/testfix"
)

// memFile adapts a byte slice to FileAt.
type memFile struct{ b []byte }

func (m memFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(m.b)) {
		return 0, bytes.ErrTooLarge
	}
	n := copy(p, m.b[off:])
	if n < len(p) {
		return n, bytes.ErrTooLarge
	}
	return n, nil
}

func TestIdentifyPE32(t *testing.T) {
	data := testfix.PE32()
	tgt := &binary.Target{Format: binary.FormatPE}
	if err := Identify(tgt, memFile{data}, int64(len(data))); err != nil {
		t.Fatalf("identify: %v", err)
	}
	if tgt.Class != "PE32" {
		t.Errorf("class = %q, want PE32", tgt.Class)
	}
	if tgt.Arch != "x86" {
		t.Errorf("arch = %q, want x86", tgt.Arch)
	}
	if tgt.OSType != "Windows" {
		t.Errorf("os = %q, want Windows", tgt.OSType)
	}
	if tgt.Type != "EXE" {
		t.Errorf("type = %q, want EXE", tgt.Type)
	}
	if tgt.Entry != 0x1000 {
		t.Errorf("entry = %#x, want %#x", tgt.Entry, 0x1000)
	}
	needed := tgt.Needed
	if len(needed) != 1 || needed[0] != "msvcrt.dll" {
		t.Errorf("needed = %v, want [msvcrt.dll]", needed)
	}
	if len(tgt.CompilerHints) == 0 {
		t.Error("COFF timestamp hint missing")
	}
}

func TestSections(t *testing.T) {
	data := testfix.PE32()
	pf, err := Open(memFile{data}, int64(len(data)))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	secs := pf.Sections()
	if len(secs) != 2 {
		t.Fatalf("sections = %d, want 2", len(secs))
	}
	if secs[0].Name != ".text" || secs[0].Virtual != 0x1000 || secs[0].Offset != 0x200 {
		t.Errorf("text section wrong: %+v", secs[0])
	}
	// .text is executable; .idata is not.
	if len(secs[0].Flags) == 0 || contains(secs[0].Flags, "X") == false {
		t.Errorf(".text should be executable: %+v", secs[0].Flags)
	}
	if contains(secs[1].Flags, "X") {
		t.Errorf(".idata should not be executable: %+v", secs[1].Flags)
	}
}

func TestImports(t *testing.T) {
	data := testfix.PE32()
	pf, err := Open(memFile{data}, int64(len(data)))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	imps := pf.Imports()
	if len(imps) != 2 {
		t.Fatalf("imports = %d, want 2: %+v", len(imps), imps)
	}
	want := map[string]string{"printf": "msvcrt.dll", "exit": "msvcrt.dll"}
	for _, im := range imps {
		if im.Library != want[im.Name] {
			t.Errorf("import %s from %s, want %s", im.Name, im.Library, want[im.Name])
		}
	}
}

func TestNotPE(t *testing.T) {
	// A non-MZ input must surface ErrNotPE.
	var m memFile
	if _, err := Open(m, 0); err != ErrNotPE {
		t.Fatalf("expected ErrNotPE, got %v", err)
	}
	// MZ but no PE signature -> ErrNotPE.
	if _, err := Open(memFile{[]byte("MZ\x00\x00")}, 4); err != ErrNotPE {
		t.Fatalf("MZ without PE signature: expected ErrNotPE, got %v", err)
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
