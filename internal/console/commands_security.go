// commands_security.go implements the SECURITY and SYSTEM console commands:
// attack surface, the full analysis pipeline, findings/reporting, dynamic
// planning, and self-update. Findings are observations with confidence —
// never verdicts — and every command keeps saying so.
package console

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-aksum/internal/binary"
	"github.com/QYVORA/qyvora-aksum/internal/dynamic"
	"github.com/QYVORA/qyvora-aksum/internal/engine"
	"github.com/QYVORA/qyvora-aksum/internal/findings"
	"github.com/QYVORA/qyvora-aksum/internal/selfupdate"
	"github.com/QYVORA/qyvora-aksum/internal/updatecfg"
)

// runSurface aggregates the target's attack surface.
func runSurface(c *Console, p *Parsed) error {
	rep, err := c.sess.Surface()
	if err != nil {
		c.failf("%v", err)
		return nil
	}
	if emitJSON(c, p, rep) {
		return nil
	}
	c.phase("SURFACE", "%d imports (%d security-relevant), %d exported functions, %d classified strings",
		rep.TotalImports, rep.RiskyImports, rep.ExportFuncs, rep.SurfaceStrs)
	engine.RenderSurface(c.out, rep)
	return nil
}

// runAnalyze executes the full static pipeline and stores its report.
func runAnalyze(c *Console, p *Parsed) error {
	ac, err := requireContext(c)
	if err != nil {
		return nil
	}
	minSev := findings.Severity(strings.ToLower(p.Str("min-severity")))
	if minSev == "" {
		minSev = findings.SevInfo
	}
	if !engine.ValidMinSeverity(minSev) {
		return fmt.Errorf("invalid --min-severity %q (info, low, medium, high, critical)", minSev)
	}
	report, rerr := engine.RunPipeline(ac, engine.PipelineOptions{MinSeverity: minSev}, nil)
	if rerr != nil {
		return rerr
	}
	c.sess.setReport(report)
	if emitJSON(c, p, report) {
		return nil
	}
	s := report.Summary
	c.phase("ANALYSIS", "%d functions, %d strings (%d security-relevant), %d imports",
		s.Functions, s.StringsExtracted, s.StringsClassified, s.Imports)
	c.phase("ANALYSIS", "%d call sites resolved (%d validated by dataflow)",
		s.CallSitesResolved, s.ValidatedCount)
	c.phase("FINDINGS", "%d finding(s) at or above %s severity", len(report.Findings), minSev)
	if len(report.Findings) > 0 {
		engine.RenderFindings(c.out, report.Findings, false)
		c.printf("\n  By severity:   %s\n  By confidence: %s\n",
			formatCounts(s.BySeverity), formatCounts(s.ByConfidence))
	}
	return nil
}

func formatCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// runFindings displays stored findings, running the pipeline when needed.
func runFindings(c *Console, p *Parsed) error {
	report, err := c.sess.Report()
	if err != nil {
		c.failf("%v", err)
		return nil
	}
	if emitJSON(c, p, report.Findings) {
		return nil
	}
	c.phase("FINDINGS", "%d finding(s)", len(report.Findings))
	engine.RenderFindings(c.out, report.Findings, p.Bool("details"))
	return nil
}

// runReport writes the machine-readable analysis report to a file.
func runReport(c *Console, p *Parsed) error {
	if p.ArgsLen() != 1 {
		return fmt.Errorf("report requires an output path: see 'help report'")
	}
	report, err := c.sess.Report()
	if err != nil {
		c.failf("%v", err)
		return nil
	}
	data, merr := json.MarshalIndent(report, "", "  ")
	if merr != nil {
		return merr
	}
	path := expandHome(p.Arg(0))
	if werr := os.WriteFile(path, append(data, '\n'), 0o600); werr != nil {
		return fmt.Errorf("write report: %w", werr)
	}
	c.ok("Report written to %s (%d findings)", path, len(report.Findings))
	return nil
}

// runDynamic builds a validated dynamic-analysis plan. This build never
// executes: 'run' is refused and 'plan' only prints what would run.
func runDynamic(c *Console, p *Parsed) error {
	t := c.sess.Target
	if t == nil {
		c.warnf("No target loaded.")
		c.printf("Use: open <binary>\n")
		return nil
	}
	sub := strings.ToLower(p.Arg(0))
	switch sub {
	case "plan":
		return dynamicPlan(c, p, t)
	case "run":
		return errors.New("no dynamic-execution backend is bundled with this build: " +
			"aksum refuses to execute binaries without a real isolation boundary; " +
			"use 'dynamic plan' to produce a validated plan for your own sandbox")
	default:
		return fmt.Errorf("dynamic requires a subcommand: plan | run")
	}
}

func dynamicPlan(c *Console, p *Parsed, t *binary.Target) error {
	if t.Format == binary.FormatRaw {
		// Unidentified content is a property of the target, not of the
		// invocation — refuse honestly instead of planning execution.
		return fmt.Errorf("%s: format %q is unidentified; refusing to plan execution of unknown content",
			t.Path, t.Format)
	}
	pol, err := dynamicPolicyFromFlags(p)
	if err != nil {
		return err
	}
	plan, berr := dynamic.BuildPlan(t, p.Strs("arg"), pol)
	if berr != nil {
		return berr
	}
	data, merr := json.MarshalIndent(plan, "", "  ")
	if merr != nil {
		return merr
	}
	c.printf("%s\n", data)
	c.warnf("Plan validated; this build performs no execution — feed the plan to an external sandbox backend of your own")
	return nil
}

func dynamicPolicyFromFlags(p *Parsed) (dynamic.Policy, error) {
	pol := dynamic.Defaults()
	if v := p.Str("timeout"); v != "" {
		d, derr := time.ParseDuration(v)
		if derr != nil {
			return pol, fmt.Errorf("invalid --timeout %q (e.g. 5s, 1m)", v)
		}
		pol.Timeout = d
	}
	pol.AllowNetwork = p.Bool("allow-network")
	pol.AllowFileWrite = p.Bool("allow-file-write")
	if v := p.Int("max-output-bytes", 0); v > 0 {
		pol.MaxOutputBytes = v
	}
	pol.ConsentConfirmed = p.Bool("yes")
	return pol, nil
}

// runUpdate checks GitHub releases and installs a newer verified build.
func runUpdate(c *Console, p *Parsed) error {
	opts := selfupdate.Options{Out: c.out}
	if p.Bool("json") {
		opts.Quiet = true
	}
	res, err := selfupdate.Run(c.OpContext(), updatecfg.Config(), opts)
	if emitJSON(c, p, updatePayload(res, err)) {
		return nil
	}
	if err != nil {
		var ue *selfupdate.UpdateError
		if errors.As(err, &ue) && ue.Kind == selfupdate.KindPermission && ue.Path() != "" {
			return fmt.Errorf("%s\n\n%s", ue.Error(),
				selfupdate.PermissionHint(updatecfg.Config().ToolName, ue.Path()))
		}
		return err
	}
	switch res.Status {
	case selfupdate.StatusUpdated:
		c.ok("Updated %s -> %s at %s", res.Current, res.Latest, res.Path)
	case selfupdate.StatusCurrent:
		c.ok("Already on the latest release (%s)", res.Current)
	case selfupdate.StatusNewerInstalled:
		c.ok("Installed version %s is newer than latest release %s; nothing done",
			res.Current, res.Latest)
	}
	return nil
}

func updatePayload(res selfupdate.Result, err error) map[string]string {
	payload := map[string]string{
		"framework": "aksum",
		"command":   "update",
		"installed": res.Current,
		"latest":    res.Latest,
	}
	switch res.Status {
	case selfupdate.StatusUpdated:
		payload["status"] = "updated"
		payload["path"] = res.Path
	case selfupdate.StatusCurrent:
		payload["status"] = "current"
	case selfupdate.StatusNewerInstalled:
		payload["status"] = "newer_installed"
	}
	if err != nil {
		payload["status"] = "failed"
		payload["error"] = err.Error()
	}
	return payload
}
