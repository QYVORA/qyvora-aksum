package validation

import (
	"testing"

	"github.com/QYVORA/qyvora-aksum/internal/dataflow"
	"github.com/QYVORA/qyvora-aksum/internal/findings"
)

func site(addr uint64, callee, caller, strArg string) dataflow.CallSite {
	s := dataflow.CallSite{Addr: addr, Callee: callee, Caller: caller, ViaPLT: true}
	if strArg != "" {
		s.Args = append(s.Args, dataflow.ResolvedArg{
			Register: "rdi", Position: 0, Kind: dataflow.KindString, Text: strArg,
		})
	}
	return s
}

func TestEscalatesImportFindingWithCorroboratedCallSite(t *testing.T) {
	b := findings.New("dangerous-imports", "strcpy() imported", "hardening",
		findings.SevMedium, findings.ConfCandidate).
		Describe("d", "r", "v").Add("import", "strcpy", "")
	fs := []findings.Finding{b.Build()}
	res := Validate(fs, []dataflow.CallSite{
		site(0x4010aa, "strcpy", "main", "/tmp/pwn"),
	})
	f := fs[0]

	if res.Upgraded != 1 {
		t.Fatalf("Upgraded = %d, want 1 (%+v)", res.Upgraded, res)
	}
	if f.Confidence != findings.ConfValidated {
		t.Errorf("confidence = %s, want VALIDATED", f.Confidence)
	}
	var found bool
	for _, e := range f.Evidence {
		if e.Kind == KindCallSite {
			found = true
			if e.Location != "0x4010aa" {
				t.Errorf("callsite location = %q", e.Location)
			}
		}
	}
	if !found {
		t.Errorf("no callsite evidence appended: %+v", f.Evidence)
	}
}

func TestDoesNotTouchUnrelatedFindings(t *testing.T) {
	f := findings.New("weak-crypto-signals", "md5 referenced", "crypto",
		findings.SevLow, findings.ConfSuspected).
		Describe("d", "r", "v").Add("string", "0x402000", "md5").Build()

	res := Validate([]findings.Finding{f}, []dataflow.CallSite{
		site(0x401000, "strcpy", "main", "x"),
	})
	if res.Upgraded != 0 || f.Confidence != findings.ConfSuspected {
		t.Errorf("finding changed without corroboration: %+v res=%+v", f, res)
	}
}

func TestNeverExceedsValidated(t *testing.T) {
	fs := []findings.Finding{findings.New("dangerous-imports", "system() imported", "exec",
		findings.SevHigh, findings.ConfValidated).
		Describe("d", "r", "v").Add("import", "system", "").Build()}

	res := Validate(fs, []dataflow.CallSite{
		site(0x402000, "system", "run_cmd", "/bin/sh"),
	})
	f := fs[0]
	if res.Upgraded != 0 {
		t.Errorf("already-VALIDATED counted as upgraded: %+v", res)
	}
	if f.Confidence != findings.ConfValidated || len(f.Evidence) != 2 {
		t.Errorf("evidence should append without confidence change: %s %d",
			f.Confidence, len(f.Evidence))
	}
}

func TestCallSitesWithoutStringArgsDoNotCorroborate(t *testing.T) {
	f := findings.New("dangerous-imports", "gets() imported", "io",
		findings.SevHigh, findings.ConfCandidate).
		Describe("d", "r", "v").Add("import", "gets", "").Build()

	cs := dataflow.CallSite{Addr: 0x10, Callee: "gets", Caller: "m"}
	cs.Args = append(cs.Args, dataflow.ResolvedArg{
		Register: "rdi", Kind: dataflow.KindConstant, Value: 5})
	res := Validate([]findings.Finding{f}, []dataflow.CallSite{cs})

	if res.Upgraded != 0 || len(f.Evidence) != 1 {
		t.Errorf("constant-only call site must not corroborate: %+v", res)
	}
}

func TestDeterministicEvidenceOrdering(t *testing.T) {
	fs := make([]findings.Finding, 0, 1)
	b := findings.New("dangerous-imports", "strcpy() imported", "hardening",
		findings.SevMedium, findings.ConfCandidate).
		Describe("d", "r", "v").Add("import", "strcpy", "")
	fs = append(fs, b.Build())

	sites := []dataflow.CallSite{
		site(0x402000, "strcpy", "b", "zz"),
		site(0x401000, "strcpy", "a", "aa"), // out of order on purpose
	}
	res := Validate(fs, sites)
	if res.Upgraded != 1 {
		t.Fatalf("Upgraded = %d", res.Upgraded)
	}
	locs := []string{}
	for _, e := range fs[0].Evidence {
		if e.Kind == KindCallSite {
			locs = append(locs, e.Location)
		}
	}
	if len(locs) != 2 || locs[0] != "0x401000" || locs[1] != "0x402000" {
		t.Errorf("call-site evidence not address-sorted: %v", locs)
	}
}
