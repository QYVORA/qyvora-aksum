package testfix

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestELF64IsDeterministic(t *testing.T) {
	a := sha256.Sum256(ELF64(ExecNX))
	b := sha256.Sum256(ELF64(ExecNX))
	if !bytes.Equal(a[:], b[:]) {
		t.Fatalf("fixture not deterministic: %s vs %s",
			hex.EncodeToString(a[:8]), hex.EncodeToString(b[:8]))
	}
	t.Logf("ExecNX sha256=%s", hex.EncodeToString(a[:]))

	c := sha256.Sum256(ELF64(SharedPIE))
	d := sha256.Sum256(ELF64(ExecNoStack))
	if bytes.Equal(a[:], c[:]) || bytes.Equal(a[:], d[:]) {
		t.Fatal("distinct variants must produce distinct bytes")
	}
}

func TestVariantsAreWellFormedEnoughForDebugElf(t *testing.T) {
	// The loader test in internal/loader exercises real parsing; here we
	// only assert structural invariants cheaply.
	for _, v := range []Variant{ExecNX, SharedPIE, ExecNoStack} {
		data := ELF64(v)
		if len(data) < ehsize+phentsize+shentsize*3 {
			t.Fatalf("%d: fixture too small: %d", v, len(data))
		}
		if data[0] != 0x7f || string(data[1:4]) != "ELF" {
			t.Fatalf("%d: bad magic", v)
		}
	}
}
