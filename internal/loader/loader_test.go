package loader

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/QYVORA/qyvora-aksum/internal/testfix"
)

func TestOpenMissingFile(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestOpenDirectory(t *testing.T) {
	if _, err := Open(t.TempDir()); err == nil {
		t.Fatal("expected error for directory target")
	}
}

func TestOpenRawBytesIsRAWFormat(t *testing.T) {
	p := filepath.Join(t.TempDir(), "blob.bin")
	if err := os.WriteFile(p, []byte{0x12, 0x34, 0x56, 0x78, 0x9a}, 0o600); err != nil {
		t.Fatal(err)
	}
	tgt, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if tgt.Format != "RAW" {
		t.Fatalf("random bytes must be RAW, got %s", tgt.Format)
	}
	if tgt.SHA256 == "" {
		t.Fatal("sha256 must always be computed")
	}
}

func TestOpenShortFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tiny")
	if err := os.WriteFile(p, []byte{0x7f}, 0o600); err != nil {
		t.Fatal(err)
	}
	tgt, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if tgt.Format != "RAW" {
		t.Fatalf("truncated magic must fall back to RAW, got %s", tgt.Format)
	}
}

func TestOpenPEIdentifies(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sample.exe")
	if err := os.WriteFile(p, testfix.PE32(), 0o600); err != nil {
		t.Fatal(err)
	}
	tgt, err := Open(p)
	if err != nil {
		t.Fatalf("open PE: %v", err)
	}
	if tgt.Format != "PE" {
		t.Fatalf("format = %s, want PE", tgt.Format)
	}
	if tgt.Arch != "x86" || tgt.Class != "PE32" {
		t.Errorf("identification = %s/%s, want PE32/x86", tgt.Class, tgt.Arch)
	}
	if tgt.Entry != 0x1000 {
		t.Errorf("entry = %#x, want %#x", tgt.Entry, 0x1000)
	}
	if tgt.SHA256 == "" {
		t.Error("sha256 must always be computed")
	}
}

func TestOpenSelfIsELFOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF fixture requires linux")
	}
	self, err := os.Executable()
	if err != nil {
		t.Skip("cannot locate test binary")
	}
	tgt, err := Open(self)
	if err != nil {
		t.Fatal(err)
	}
	if tgt.Format != "ELF" {
		t.Fatalf("test binary should identify as ELF, got %s", tgt.Format)
	}
	if tgt.Entry == 0 {
		t.Error("entry point must be nonzero for an executable ELF")
	}
}
