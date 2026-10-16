package cli

import (
	"sort"
	"testing"

	"github.com/spf13/cobra"
)

// analysisModules is every aksum module that must live under the recon tier.
var analysisModules = []string{
	"analyze", "binary", "calls", "cfg", "disassemble", "dynamic",
	"functions", "imports", "pe", "sections", "segments", "strings",
	"surface", "symbols", "xrefs",
}

// TestTierGrammarTree locks the shared tier grammar: every analysis module is
// reachable as `aksum recon <module>`, the exploit and report tiers exist so
// the shape is uniform across tools, and every pre-tier top-level invocation
// still resolves as a hidden alias so existing scripts do not break.
func TestTierGrammarTree(t *testing.T) {
	root := newRootCmd()

	recon := childNamed(root, "recon")
	if recon == nil {
		t.Fatal("root has no recon tier")
	}
	for _, tier := range []string{"exploit", "report"} {
		if childNamed(root, tier) == nil {
			t.Errorf("root has no %s tier", tier)
		}
	}

	got := make([]string, 0, len(recon.Commands()))
	for _, c := range recon.Commands() {
		got = append(got, c.Name())
	}
	sort.Strings(got)
	if len(got) != len(analysisModules) {
		t.Fatalf("recon modules = %v, want %v", got, analysisModules)
	}
	for i, name := range got {
		if name != analysisModules[i] {
			t.Fatalf("recon modules = %v, want %v", got, analysisModules)
		}
	}

	for _, name := range analysisModules {
		alias := childNamed(root, name)
		if alias == nil {
			t.Errorf("module %q has no top-level alias", name)
			continue
		}
		if !alias.Hidden {
			t.Errorf("top-level alias %q must be hidden", name)
		}
	}
}

func childNamed(parent *cobra.Command, name string) *cobra.Command {
	for _, c := range parent.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}
