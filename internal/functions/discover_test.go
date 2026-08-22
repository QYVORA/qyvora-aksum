package functions

import (
	"os"
	"runtime"
	"testing"

	"github.com/QYVORA/qyvora-aksum/internal/analysis/structure"
	x86dec "github.com/QYVORA/qyvora-aksum/internal/disasm/x86"
)

// TestDiscoverOnTestBinary exercises the full discovery pipeline against the
// test binary itself (a real ELF on linux) — the deterministic fixture the
// platform can always provide.
func TestDiscoverOnTestBinary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF fixture requires linux")
	}
	self, err := os.Executable()
	if err != nil {
		t.Skip("cannot locate test binary")
	}
	im, err := structure.Open(self)
	if err != nil {
		t.Skipf("test binary not ELF-parseable here: %v", err)
	}
	defer im.Close() //nolint:errcheck // read-only

	funcs, err := Discover(im, x86dec.New64(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(funcs) == 0 {
		t.Fatal("discovery found nothing in a real binary")
	}
	for i := 1; i < len(funcs); i++ {
		if funcs[i].Address <= funcs[i-1].Address {
			t.Fatalf("functions not sorted: %#x after %#x", funcs[i].Address, funcs[i-1].Address)
		}
		if funcs[i].Size <= 0 {
			t.Fatalf("function at %#x has non-positive size", funcs[i].Address)
		}
	}
	// Every function must carry at least one evidence source and a
	// confidence level from the documented vocabulary.
	for _, f := range funcs {
		if len(f.Sources) == 0 {
			t.Fatalf("function %#x has no provenance", f.Address)
		}
		switch f.Confidence {
		case ConfHigh, ConfMedium, ConfLow:
		default:
			t.Fatalf("unknown confidence %q at %#x", f.Confidence, f.Address)
		}
	}
}

func TestSeedSetConfidenceEscalation(t *testing.T) {
	s := newSeedSet()
	s.add(0x1000, "sub_a", ConfMedium, "call target", false)
	s.add(0x1000, "real_name", ConfHigh, "symbol", false)
	info := s.byAddr[0x1000]
	if info.conf != ConfHigh || info.name != "real_name" {
		t.Fatalf("high-confidence source must win: %+v", info)
	}
	if len(info.sources) != 2 {
		t.Fatalf("sources should accumulate: %v", info.sources)
	}
}
