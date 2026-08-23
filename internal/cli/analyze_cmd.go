package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-aksum/internal/engine"
	"github.com/QYVORA/qyvora-aksum/internal/events"
	"github.com/QYVORA/qyvora-aksum/internal/findings"
	"github.com/QYVORA/qyvora-aksum/internal/output"
)

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
			if !engine.ValidMinSeverity(findings.Severity(minSev)) {
				return usagef("invalid --min-severity %q (info, low, medium, high, critical)", minSev)
			}

			// Event stream: opened before any stage so every phase is
			// bracketed even on early failure.
			var stream *events.Stream
			if w, closer, ok := eventsWriter(); ok {
				defer closer() //nolint:errcheck // best-effort log close
				stream = events.NewStream(w)
			}
			emitEvent := func(name string, data map[string]any) {
				if stream != nil {
					stream.Emit(events.LevelInfo, name, data)
				}
			}

			emitEvent(events.ScanStarted, map[string]any{"target": path})

			ac, err := engine.OpenAnalysis(path)
			if err != nil {
				return err
			}
			defer ac.Close() //nolint:errcheck // read-only

			obs := &engine.Observer{
				Phase: func(name string, start bool, data map[string]any) {
					if start {
						emitEvent(events.PhaseStarted, map[string]any{"phase": name})
						return
					}
					if data != nil {
						data["phase"] = name
					}
					emitEvent(events.PhaseCompleted, data)
				},
				Validation: func(done bool, data map[string]any) {
					if done {
						emitEvent(events.ValidationCompleted, data)
					} else {
						emitEvent(events.ValidationStarted, data)
					}
				},
				Finding: func(f findings.Finding) {
					emitEvent(events.FindingDiscovered, map[string]any{
						"id": f.ID, "rule": f.Rule,
						"severity": string(f.Severity), "confidence": string(f.Confidence),
						"title": f.Title,
					})
				},
			}

			report, rerr := engine.RunPipeline(ac, engine.PipelineOptions{
				MinSeverity: findings.Severity(minSev),
			}, obs)
			if rerr != nil {
				return rerr
			}

			p := newPrinter()
			if p.Format() == "json" {
				if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
					return err
				}
			} else {
				renderAnalyze(p, report)
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
				emitEvent(events.ReportGenerated, map[string]any{"path": outPath, "findings": len(report.Findings)})
			}
			emitEvent(events.ScanCompleted, map[string]any{
				"target":              path,
				"functions":           report.Summary.Functions,
				"strings_extracted":   report.Summary.StringsExtracted,
				"call_sites_resolved": report.Summary.CallSitesResolved,
				"findings_reported":   len(report.Findings),
				"findings_validated":  report.Summary.ValidatedCount,
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&minSev, "min-severity", "info", "minimum reported severity: info, low, medium, high, critical")
	cmd.Flags().StringVar(&outPath, "report", "", "also write the JSON report to this path")
	return cmd
}

func renderAnalyze(p *output.Printer, r *engine.AnalyzeReport) {
	t := r.Target
	p.Info("ANALYSIS", fmt.Sprintf("Target: %s (%s/%s)", t.Path, t.Format, t.Arch))
	p.Info("ANALYSIS", fmt.Sprintf("Discovered %d functions; extracted %d strings (%d security-relevant); %d imports; %d call sites resolved (%d finding(s) validated).",
		r.Summary.Functions, r.Summary.StringsExtracted, r.Summary.StringsClassified, r.Summary.Imports,
		r.Summary.CallSitesResolved, r.Summary.ValidatedCount))

	fmt.Printf("\nFINDINGS (%d)\n", len(r.Findings))
	engine.RenderFindings(os.Stdout, r.Findings, true)
	fmt.Printf("\n%d finding(s); by severity %v; by confidence %v\n",
		len(r.Findings), r.Summary.BySeverity, r.Summary.ByConfidence)
}
