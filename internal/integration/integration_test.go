// Package integration exercises the full static-analysis pipeline end-to-
// end against crafted deterministic fixtures, plus negative paths on
// corrupt inputs. These tests pin cross-package behavior that unit tests
// per package cannot: loader -> identification -> enumeration ->
// discovery -> checks.
package integration

import (
	"os"
	"path/filepath"
	"testing"

	strscan "github.com/QYVORA/qyvora-aksum/internal/analysis/strings"
	"github.com/QYVORA/qyvora-aksum/internal/analysis/structure"
	"github.com/QYVORA/qyvora-aksum/internal/binary"
	"github.com/QYVORA/qyvora-aksum/internal/checks"
	"github.com/QYVORA/qyvora-aksum/internal/disasm/x86"
	"github.com/QYVORA/qyvora-aksum/internal/functions"
	"github.com/QYVORA/qyvora-aksum/internal/loader"
	"github.com/QYVORA/qyvora-aksum/internal/testfix"
)

func writeFixture(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFullPipelineOnCraftedELF(t *testing.T) {
	path := writeFixture(t, testfix.ELF64(testfix.ExecNX))

	tgt, err := loader.Open(path)
	if err != nil {
		t.Fatalf("identify: %v", err)
	}
	if tgt.Format != binary.FormatELF || tgt.Arch != "x86-64" {
		t.Fatalf("identification = %s/%s", tgt.Format, tgt.Arch)
	}
	if tgt.NX != binary.PropertyEnabled || tgt.PIE != binary.PropertyDisabled {
		t.Errorf("properties NX=%s PIE=%s", tgt.NX, tgt.PIE)
	}
	if tgt.SHA256 == "" {
		t.Error("loader must hash every target")
	}

	im, err := structure.Open(path)
	if err != nil {
		t.Fatalf("structure: %v", err)
	}
	defer im.Close() //nolint:errcheck // read-only

	var textSeen bool
	for _, s := range im.Sections() {
		if s.Name == ".text" && s.Size > 0 {
			textSeen = true
		}
	}
	if !textSeen {
		t.Error(".text not enumerated")
	}

	fn, err := functions.Discover(im, x86.New64(), functions.Options{})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(fn) == 0 {
		t.Fatal("no function discovered at the known code address")
	}
	if fn[0].Address != 0x400000 {
		t.Errorf("entry function at %#x, want 0x400000", fn[0].Address)
	}
	if len(fn[0].Instructions) != 3 { // endbr64; xor eax,eax; ret
		t.Errorf("decoded %d instructions, want 3", len(fn[0].Instructions))
	}

	extracted := strscan.Extract(im.RawFile(), strscan.Options{})
	ctx := &checks.Context{
		Target:   im.Target,
		Imports:  im.Imports(),
		Segments: im.Segments(),
		Strings:  strscan.ClassifyAll(extracted),
	}
	found, err := checks.Run(ctx)
	if err != nil {
		t.Fatalf("checks: %v", err)
	}
	rules := map[string]findingsConf{}
	for _, f := range found {
		rules[f.Rule] = findingsConf{string(f.Severity), string(f.Confidence)}
	}
	nc, ok := rules["no-pie"]
	if !ok {
		t.Fatalf("no-pie finding missing from %v", ruleNames(rules))
	}
	if nc.conf != "OBSERVED" {
		t.Errorf("no-pie confidence = %s, want OBSERVED (direct header read)", nc.conf)
	}
	if _, ok := rules["no-relro"]; !ok {
		t.Error("no-relro finding missing")
	}
}

type findingsConf struct{ sev, conf string }

func ruleNames(m map[string]findingsConf) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestNegativeCorruptMagicFallsBackToRaw(t *testing.T) {
	tgt, err := loader.Open(writeFixture(t, testfix.Corrupt(testfix.ELF64(testfix.ExecNX))))
	if err != nil {
		t.Fatalf("corrupt magic must degrade to RAW, got error: %v", err)
	}
	if tgt.Format != binary.FormatRaw {
		t.Errorf("format = %s, want RAW", tgt.Format)
	}
}

func TestNegativeTruncatedHeader(t *testing.T) {
	full := testfix.ELF64(testfix.ExecNX)
	tgt, err := loader.Open(writeFixture(t, testfix.Truncate(full, 20)))
	if err != nil {
		t.Fatalf("truncated file must degrade gracefully, got error: %v", err)
	}
	if tgt.Format != binary.FormatRaw {
		t.Errorf("format = %s, want RAW for unparseable content", tgt.Format)
	}
}
