// Package validation implements the confidence-escalation pass of the
// findings pipeline.
//
// A finding starts at whatever confidence its rule could honestly justify
// (import presence = CANDIDATE, metadata absence = SUSPECTED, direct
// property reads = OBSERVED). Validation promotes a finding one step —
// never beyond VALIDATED — when an independent analysis stage corrob-
// orates it:
//
//   - dataflow resolves a concrete call site to the same imported symbol,
//     proving reachability of the risky API rather than mere presence;
//   - the call site carries a statically-resolved string argument, tying
//     the API to specific data.
//
// CONFIRMED stays reserved for dynamic confirmation that this build does
// not fabricate. Escalation appends its own evidence records so the audit
// trail shows exactly which observation justified the promotion.
package validation

import (
	"fmt"
	"sort"

	"github.com/QYVORA/qyvora-aksum/internal/dataflow"
	"github.com/QYVORA/qyvora-aksum/internal/findings"
)

// maxSitesPerFinding bounds appended call-site evidence per finding.
const maxSitesPerFinding = 4

// Evidence kind added by this pass.
const KindCallSite = "callsite"

// Result summarizes what the pass changed.
type Result struct {
	Upgraded     int      `json:"upgraded"`
	Corroborated []string `json:"corroborated_ids,omitempty"` // finding IDs promoted
}

// callSummary is a compact per-symbol view of resolved call sites.
type callSummary struct {
	sites []dataflow.CallSite // only sites carrying >=1 string argument
}

// Validate escalates corroborated findings in place and returns a summary.
func Validate(fs []findings.Finding, sites []dataflow.CallSite) Result {
	bySymbol := make(map[string]*callSummary)
	for _, s := range sites {
		if len(s.Args) == 0 {
			continue
		}
		hasStr := false
		for _, a := range s.Args {
			if a.Kind == dataflow.KindString {
				hasStr = true
				break
			}
		}
		if !hasStr {
			continue
		}
		cs, ok := bySymbol[s.Callee]
		if !ok {
			cs = &callSummary{}
			bySymbol[s.Callee] = cs
		}
		cs.sites = append(cs.sites, s)
	}
	for _, cs := range bySymbol {
		sort.Slice(cs.sites, func(i, j int) bool { return cs.sites[i].Addr < cs.sites[j].Addr })
	}

	res := Result{Corroborated: []string{}}
	for i := range fs {
		f := &fs[i]
		var syms []string
		for _, e := range f.Evidence {
			if e.Kind == "import" && e.Location != "" {
				syms = append(syms, e.Location)
			}
		}
		if len(syms) == 0 {
			continue
		}
		sort.Strings(syms)

		var added []findings.Evidence
		for _, sym := range syms {
			cs, ok := bySymbol[sym]
			if !ok {
				continue
			}
			for _, site := range cs.sites {
				if len(added) >= maxSitesPerFinding {
					break
				}
				added = append(added, findings.Evidence{
					Kind:     KindCallSite,
					Location: fmt.Sprintf("%#x", site.Addr),
					Detail:   fmt.Sprintf("%s calls %s with statically-resolved argument %q", site.Caller, site.Callee, firstStringArg(site)),
				})
			}
		}
		if len(added) == 0 {
			continue
		}

		if f.Confidence.Rank() < findings.ConfValidated.Rank() {
			f.Confidence = findings.ConfValidated
			res.Upgraded++
			res.Corroborated = append(res.Corroborated, f.ID)
		}
		f.Evidence = append(f.Evidence, added...)
	}
	return res
}

func firstStringArg(site dataflow.CallSite) string {
	best := ""
	longest := 0
	for _, a := range site.Args {
		if a.Kind == dataflow.KindString && len(a.Text) > longest {
			best, longest = a.Text, len(a.Text)
		}
	}
	return best
}
