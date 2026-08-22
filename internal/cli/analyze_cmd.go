package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	strscan "github.com/QYVORA/qyvora-aksum/internal/analysis/strings"
	"github.com/QYVORA/qyvora-aksum/internal/binary"
	"github.com/QYVORA/qyvora-aksum/internal/checks"
	"github.com/QYVORA/qyvora-aksum/internal/dataflow"
	"github.com/QYVORA/qyvora-aksum/internal/events"
	"github.com/QYVORA/qyvora-aksum/internal/findings"
	"github.com/QYVORA/qyvora-aksum/internal/output"
	"github.com/QYVORA/qyvora-aksum/internal/validation"
)

// sanitizeTerminal strips control characters from binary-derived text
// before it reaches the terminal (spec section 48).
var reCtrl = regexp.MustCompile("[\x00-\x1f\x7f]")

func sanitizeTerminal(s string) string { return reCtrl.ReplaceAllString(s, "") }

// AnalyzeReport is the full-pipeline machine-readable result.
type AnalyzeReport struct {
	Framework string             `json:"framework"` // always "aksum"
	Schema    string             `json:"schema_version"`
	Target    *binary.Target     `json:"target"`
	Summary   analyzeSummary     `json:"summary"`
	Findings  []findings.Finding `json:"findings"`
}

type analyzeSummary struct {
	Functions         int            `json:"functions_discovered"`
	StringsExtracted  int            `json:"strings_extracted"`
	StringsClassified int            `json:"strings_classified"`
	Imports           int            `json:"imports"`
	CallSitesResolved int            `json:"call_sites_resolved"`
	ValidatedCount    int            `json:"findings_validated"`
	BySeverity        map[string]int `json:"by_severity"`
	ByConfidence      map[string]int `json:"by_confidence"`
}

func newAnalyzeCmd() *cobra.Command {
	var minSev string
	var outPath string
	cmd := &cobra.Command{
		Use:   "analyze <target>",
		Short: "Run the full static assessment pipeline",
		Long: `Runs identification, string analysis, function discovery, cross-
reference mapping, and the static security rule set, then reports
deduplicated findings with evidence and explicit confidence.

Findings are observations, not verdicts: every record states what was
seen, why the rule fired, and what validation would confirm it.`,
		RunE: func(c *cobra.Command, args []string) error {
			path, err := oneArg(c, args)
			if err != nil {
				return err
			}
			sevRank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
			min, ok := sevRank[minSev]
			if !ok {
				return usagef("invalid --min-severity %q (info, low, medium, high, critical)", minSev)
			}

			// Event stream: opened before any stage so every phase is
			// bracketed even on early failure.
			var stream *events.Stream
			if w, closer, ok := eventsWriter(); ok {
				defer closer() //nolint:errcheck // best-effort log close
				stream = events.NewStream(w)
			}
			emit := func(name string, data map[string]any) {
				if stream != nil {
					stream.Emit(events.LevelInfo, name, data)
				}
			}
			phase := func(name string, start bool, data map[string]any) {
				if start {
					emit(events.PhaseStarted, map[string]any{"phase": name})
				} else {
					if data != nil {
						data["phase"] = name
					}
					emit(events.PhaseCompleted, data)
				}
			}

			emit(events.ScanStarted, map[string]any{"target": path})

			ac, err := openAnalysis(path)
			if err != nil {
				return err
			}
			defer ac.Close() //nolint:errcheck // read-only

			phase("strings", true, nil)
			extracted := strscan.Extract(ac.im.RawFile(), strscan.Options{})
			classified := strscan.ClassifyAll(extracted)
			phase("strings", false, map[string]any{"extracted": len(extracted), "classified": len(classified)})

			// Stage 15/19-21: resolve call-site arguments, then let the
			// validation pass corroborate rule findings with that evidence.
			phase("dataflow", true, nil)
			sites := dataflow.New(ac.im.Relocs(), ac.funcs, classified).AnalyzeAll(ac.funcs)
			phase("dataflow", false, map[string]any{"call_sites_resolved": len(sites)})

			ctx := &checks.Context{
				Target:    ac.im.Target,
				Imports:   ac.im.Imports(),
				Segments:  ac.im.Segments(),
				Strings:   classified,
				CallSites: sites,
			}
			phase("checks", true, nil)
			found, err := checks.Run(ctx)
			if err != nil {
				return err
			}
			phase("checks", false, map[string]any{"findings": len(found)})

			emit(events.ValidationStarted, map[string]any{"findings": len(found), "call_sites": len(sites)})
			vres := validation.Validate(found, sites)
			emit(events.ValidationCompleted, map[string]any{"validated": vres.Upgraded, "corroborated_existing": vres.Corroborated})

			kept := make([]findings.Finding, 0, len(found))
			for _, f := range found {
				if f.Severity.Rank() >= min {
					kept = append(kept, f)
					emit(events.FindingDiscovered, map[string]any{
						"id": f.ID, "rule": f.Rule,
						"severity": string(f.Severity), "confidence": string(f.Confidence),
						"title": f.Title,
					})
				}
			}

			report := AnalyzeReport{
				Framework: "aksum",
				Schema:    "1.0",
				Target:    ac.im.Target,
				Summary: analyzeSummary{
					Functions:         len(ac.funcs),
					StringsExtracted:  len(extracted),
					StringsClassified: len(ctx.Strings),
					Imports:           len(ctx.Imports),
					CallSitesResolved: len(sites),
					ValidatedCount:    vres.Upgraded,
					BySeverity:        severityCounts(kept),
					ByConfidence:      confidenceCounts(kept),
				},
				Findings: kept,
			}

			p := newPrinter()
			if p.Format() == "json" {
				if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
					return err
				}
			} else {
				renderAnalyze(p, &report)
			}
			if outPath != "" {
				data, merr := json.MarshalIndent(report, "", "  ")
				if merr != nil {
					return merr
				}
				if werr := os.WriteFile(outPath, append(data, '\n'), 0o600); werr != nil {
					return fmt.Errorf("write report: %w", werr)
				}
				p.Info("REPORT", "wrote "+outPath)
				emit(events.ReportGenerated, map[string]any{"path": outPath, "findings": len(kept)})
			}
			emit(events.ScanCompleted, map[string]any{
				"target":              path,
				"functions":           report.Summary.Functions,
				"strings_extracted":   report.Summary.StringsExtracted,
				"call_sites_resolved": report.Summary.CallSitesResolved,
				"findings_reported":   len(kept),
				"findings_validated":  report.Summary.ValidatedCount,
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&minSev, "min-severity", "info", "minimum reported severity: info, low, medium, high, critical")
	cmd.Flags().StringVar(&outPath, "report", "", "also write the JSON report to this path")
	return cmd
}

func severityCounts(fs []findings.Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[string(f.Severity)]++
	}
	return m
}

func confidenceCounts(fs []findings.Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[string(f.Confidence)]++
	}
	return m
}

func renderAnalyze(p *output.Printer, r *AnalyzeReport) {
	t := r.Target
	p.Info("ANALYSIS", fmt.Sprintf("Target: %s (%s/%s)", t.Path, t.Format, t.Arch))
	p.Info("ANALYSIS", fmt.Sprintf("Discovered %d functions; extracted %d strings (%d security-relevant); %d imports; %d call sites resolved (%d finding(s) validated).",
		r.Summary.Functions, r.Summary.StringsExtracted, r.Summary.StringsClassified, r.Summary.Imports,
		r.Summary.CallSitesResolved, r.Summary.ValidatedCount))
	fmt.Printf("\nFINDINGS (%d)\n", len(r.Findings))
	if len(r.Findings) == 0 {
		fmt.Println("  none at or above the selected threshold")
		return
	}
	for _, f := range r.Findings {
		fmt.Printf("\n[%s] %-8s %-10s %s\n", f.Severity, f.Confidence, f.ID, f.Title)
		fmt.Printf("  reason:     %s\n", f.Reason)
		fmt.Printf("  validation: %s\n", f.Validation)
		if len(f.Evidence) > 0 {
			locs := make([]string, 0, len(f.Evidence))
			for _, e := range f.Evidence {
				detail := ""
				if e.Detail != "" {
					detail = " (" + sanitizeTerminal(e.Detail) + ")"
				}
				locs = append(locs, e.Kind+":"+e.Location+detail)
			}
			fmt.Printf("  evidence:   %s\n", strings.Join(locs, "; "))
		}
	}
	fmt.Printf("\n%d finding(s); by severity %v; by confidence %v\n",
		len(r.Findings), r.Summary.BySeverity, r.Summary.ByConfidence)
}
