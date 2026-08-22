package checks

import (
	"testing"

	strscan "github.com/QYVORA/qyvora-aksum/internal/analysis/strings"
	"github.com/QYVORA/qyvora-aksum/internal/analysis/structure"
	"github.com/QYVORA/qyvora-aksum/internal/binary"
	"github.com/QYVORA/qyvora-aksum/internal/findings"
)

func baseTarget() *binary.Target {
	return &binary.Target{
		Format: binary.FormatELF,
		Arch:   "x86-64",
		PIE:    binary.PropertyEnabled,
		NX:     binary.PropertyEnabled,
		RELRO:  "full",
		Canary: binary.PropertyEnabled,
	}
}

func TestHardeningDisabledPropertiesReported(t *testing.T) {
	tgt := baseTarget()
	tgt.NX = binary.PropertyDisabled
	tgt.PIE = binary.PropertyDisabled
	tgt.RELRO = "none"
	fs, err := Run(&Context{Target: tgt})
	if err != nil {
		t.Fatal(err)
	}
	rules := make([]string, 0, len(fs))
	for _, f := range fs {
		rules = append(rules, f.Rule)
	}
	for _, want := range []string{"no-nx", "no-pie", "no-relro"} {
		found := false
		for _, r := range rules {
			if r == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing finding %q; got %v", want, rules)
		}
	}
}

func TestHardenedBinaryClean(t *testing.T) {
	fs, err := Run(&Context{Target: baseTarget()})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.Rule == "no-nx" || f.Rule == "no-pie" || f.Rule == "no-relro" || f.Rule == "no-canary" {
			t.Errorf("hardened target must not report %s", f.Rule)
		}
	}
}

func TestWritableExecutableSegment(t *testing.T) {
	fs, err := Run(&Context{
		Target: baseTarget(),
		Segments: []structure.Segment{
			{Type: "LOAD", Flags: "rwx", VirtualAddr: 0x1000, FileSize: 4096},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range fs {
		if f.Rule == "wx-segment" && f.Severity == findings.SevHigh {
			found = true
		}
	}
	if !found {
		t.Fatal("writable+executable segment not reported as high severity")
	}
}

func TestDangerousImportIsCandidate(t *testing.T) {
	fs, err := Run(&Context{
		Target:  baseTarget(),
		Imports: []structure.Import{{Name: "gets"}, {Name: "printf"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.Rule == "dangerous-import-gets" && f.Confidence != findings.ConfCandidate {
			t.Fatalf("dangerous import must be CANDIDATE, got %s", f.Confidence)
		}
	}
}

func TestWeakCryptoStringSuspected(t *testing.T) {
	fs, err := Run(&Context{
		Target: baseTarget(),
		Strings: []strscan.Classified{
			{Str: strscan.Str{Value: "computed with md5 algorithm", Address: 0x5000}, Confidence: "medium"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.Rule == "weak-crypto-md5" && f.Confidence != findings.ConfSuspected {
			t.Fatalf("string-only crypto signal must stay SUSPECTED, got %s", f.Confidence)
		}
	}
}

func TestRawFormatSkipsPropertyChecks(t *testing.T) {
	tgt := &binary.Target{Format: binary.FormatRaw}
	fs, err := Run(&Context{Target: tgt})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.Category == "hardening" {
			t.Fatal("raw files must not yield hardening claims")
		}
	}
}
