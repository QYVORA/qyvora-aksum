package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-script/ast"
	"github.com/QYVORA/qyvora-script/binding"
	"github.com/QYVORA/qyvora-script/interpreter"
	"github.com/QYVORA/qyvora-script/parser"

	"github.com/QYVORA/qyvora-aksum/internal/capabilities"
	"github.com/QYVORA/qyvora-aksum/internal/engine"
	"github.com/QYVORA/qyvora-aksum/internal/events"
	"github.com/QYVORA/qyvora-aksum/internal/findings"
	"github.com/QYVORA/qyvora-aksum/internal/table"
)

// newScriptCmd adds the flat `script` utility that runs the shared
// qyvora-script engine (ARCH-004 Part C). `script run <file>` executes a
// script; `script build <file>` prints a dry-run plan. A bare `script <file>`
// runs the file for convenience.
func newScriptCmd() *cobra.Command {
	run := func(dryRun bool) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, args []string) error {
			return runScriptFile(cmd, args[0], dryRun)
		}
	}
	cmd := &cobra.Command{
		Use:   "script <file>",
		Short: "run a .qs script with the shared scripting engine",
		Args:  cobra.ExactArgs(1),
		RunE:  run(false),
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "run <file>",
			Short: "execute a script file",
			Args:  cobra.ExactArgs(1),
			RunE:  run(false),
		},
		&cobra.Command{
			Use:   "build <file>",
			Short: "validate a script file and print a dry-run plan",
			Args:  cobra.ExactArgs(1),
			RunE:  run(true),
		},
	)
	return cmd
}

// runScriptFile parses (build) or executes (run) a script against aksum's
// binding.
func runScriptFile(cmd *cobra.Command, path string, dryRun bool) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading script: %w", err)
	}
	prog, err := parser.Parse(string(src))
	if err != nil {
		return usagef("%s", err.Error())
	}
	if dryRun {
		_, _ = fmt.Fprintln(os.Stdout, "script plan "+path)
		for _, line := range ast.Describe(prog) {
			_, _ = fmt.Fprintln(os.Stdout, "  -", line)
		}
		return nil
	}
	b := &scriptBinding{
		ctx:   cmd.Context(),
		allow: allowShellOut,
		cfg:   map[string]string{},
	}
	engineInst := interpreter.NewEngine(b)
	engineInst.Events = os.Stderr
	if err := engineInst.RunProgram(prog); err != nil {
		return usagef("%s", err.Error())
	}
	return nil
}

// scriptBinding implements binding.Binding against aksum's offline binary
// analysis pipeline. aksum is a monolithic analyzer, so every capability in the
// registry maps to the full static assessment pipeline that covers it: running
// "analysis.strings" runs the pipeline that performs strings analysis, and
// "assess" runs the whole pipeline explicitly.
type scriptBinding struct {
	ctx   context.Context
	allow bool
	cfg   map[string]string
	last  *engine.AnalyzeReport
}

var _ binding.Binding = (*scriptBinding)(nil)

// Capabilities lists the capability IDs this binding accepts: the tool's
// machine contract plus the whole-pipeline "assess" entry.
func (b *scriptBinding) Capabilities() []string {
	doc := capabilities.Build()
	ids := make([]string, 0, len(doc.Capabilities)+1)
	ids = append(ids, "assess")
	for _, c := range doc.Capabilities {
		ids = append(ids, c.ID)
	}
	return ids
}

// AllowShellOut reports whether exec/run.cmd may run: only with the explicit
// flag or the shared opt-in environment variable.
func (b *scriptBinding) AllowShellOut() bool { return b.allow || shellOutEnv() }

func shellOutEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(interpreter.AllowShellOutEnv))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// Call dispatches one engine capability invocation.
func (b *scriptBinding) Call(capabilityID string, args []binding.Value) (binding.Value, error) {
	switch capabilityID {
	case binding.CapEcho:
		_, _ = fmt.Fprintln(os.Stdout, asStr(args, 0))
		return nil, nil

	case binding.CapSetConfig:
		b.cfg[asStr(args, 0)] = asStr(args, 1)
		return nil, nil

	case binding.CapGetConfig:
		return b.cfg[asStr(args, 0)], nil

	case binding.CapStart:
		return nil, b.start(asStr(args, 0))

	case binding.CapStop, binding.CapIsRunning:
		if capabilityID == binding.CapIsRunning {
			return false, nil
		}
		return nil, nil

	case binding.CapShow:
		return nil, b.show(asStr(args, 0))

	case binding.CapReport:
		return nil, b.report(asStr(args, 0))

	case binding.CapProp:
		return b.prop(asStr(args, 0)), nil

	case binding.CapExec:
		return nil, b.exec(asStr(args, 0))
	}
	return nil, fmt.Errorf("unknown capability %q", capabilityID)
}

// start runs the analysis pipeline associated with a capability id.
func (b *scriptBinding) start(id string) error {
	switch id {
	case "assess", "":
		// whole pipeline
	case "dynamic.execution":
		return fmt.Errorf("live dynamic analysis is not implemented; " +
			"refused (static analysis is offline and read-only)")
	default:
		c := findCapability(id)
		if c == nil {
			return fmt.Errorf("unknown module %q", id)
		}
		if !c.Implemented {
			return fmt.Errorf("%s is not implemented", id)
		}
	}
	return b.runPipeline()
}

// target resolves the binary path under analysis from the script config.
func (b *scriptBinding) target() string {
	for _, k := range []string{"analyze.target", "assess.target", "target"} {
		if v, ok := b.cfg[k]; ok && v != "" {
			return v
		}
	}
	return ""
}

func (b *scriptBinding) minSeverity() string {
	for _, k := range []string{"analyze.severity", "assess.severity", "severity"} {
		if v, ok := b.cfg[k]; ok && v != "" {
			return v
		}
	}
	return "info"
}

// runPipeline runs the full static assessment pipeline in-process and captures
// the report for $(...) interpolation.
func (b *scriptBinding) runPipeline() error {
	target := b.target()
	if target == "" {
		return fmt.Errorf("no target set: use `set analyze.target -> \"<path>\"`")
	}
	minSev := b.minSeverity()
	if !engine.ValidMinSeverity(findings.Severity(minSev)) {
		return fmt.Errorf("invalid min-severity %q (info, low, medium, high, critical)", minSev)
	}
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
	emitEvent(events.ScanStarted, map[string]any{"target": target})

	ac, err := engine.OpenAnalysis(target)
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
	b.last = report

	p := newPrinter()
	if p.Format() == "json" {
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			return err
		}
	} else {
		renderAnalyze(p, report, os.Stdout)
	}
	emitEvent(events.ScanCompleted, map[string]any{
		"target":            target,
		"functions":         report.Summary.Functions,
		"strings_extracted": report.Summary.StringsExtracted,
		"findings_reported": len(report.Findings),
	})
	return nil
}

// show prints metadata for a module/capability id.
func (b *scriptBinding) show(id string) error {
	rows := [][]string{}
	if id == "assess" || id == "" {
		rows = append(rows, []string{"assess", "run the full static assessment pipeline"})
	}
	for _, c := range capabilities.Build().Capabilities {
		if id == "" || c.ID == id {
			impl := "yes"
			if !c.Implemented {
				impl = "no"
			}
			rows = append(rows, []string{c.ID, c.Name, impl, c.Arch})
		}
	}
	if len(rows) == 0 {
		return fmt.Errorf("unknown module %q", id)
	}
	t := table.New("capability", "name", "implemented", "arch")
	for _, r := range rows {
		t.AddRow(r...)
	}
	t.Render(os.Stdout)
	return nil
}

// report writes a JSON report artifact for the most recent run.
func (b *scriptBinding) report(path string) error {
	if b.last == nil {
		return fmt.Errorf("no assessment to report; run a module first")
	}
	if path == "" {
		path = "aksum-report.json"
	}
	data, err := json.MarshalIndent(b.last, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(os.Stdout, "report written to "+path)
	return nil
}

// prop resolves live properties for $(...) interpolation from the last run.
func (b *scriptBinding) prop(name string) binding.Value {
	t := b.last
	if t == nil {
		return nil
	}
	switch name {
	case "result.framework":
		return t.Framework
	case "result.schema", "result.schema_version":
		return t.Schema
	case "target.path":
		if t.Target != nil {
			return t.Target.Path
		}
	case "target.format":
		if t.Target != nil {
			return string(t.Target.Format)
		}
	case "target.arch":
		if t.Target != nil {
			return string(t.Target.Arch)
		}
	case "target.sha256":
		if t.Target != nil {
			return t.Target.SHA256
		}
	case "target.size":
		if t.Target != nil {
			return fmt.Sprintf("%d", t.Target.Size)
		}
	case "result.functions":
		return fmt.Sprintf("%d", t.Summary.Functions)
	case "result.strings":
		return fmt.Sprintf("%d", t.Summary.StringsExtracted)
	case "result.strings_classified":
		return fmt.Sprintf("%d", t.Summary.StringsClassified)
	case "result.imports":
		return fmt.Sprintf("%d", t.Summary.Imports)
	case "result.call_sites":
		return fmt.Sprintf("%d", t.Summary.CallSitesResolved)
	case "result.validated":
		return fmt.Sprintf("%d", t.Summary.ValidatedCount)
	case "result.findings":
		return fmt.Sprintf("%d", len(t.Findings))
	}
	return nil
}

// exec runs a one-shot aksum command line. The interpreter only reaches here
// after AllowShellOut reported true.
func (b *scriptBinding) exec(line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	code := ExecuteArgsContext(b.ctx, strings.Fields(line))
	if code != 0 {
		return fmt.Errorf("command exited with code %d", code)
	}
	return nil
}

// findCapability looks up a capability id in the tool's machine contract.
func findCapability(id string) *capabilities.Capability {
	for _, c := range capabilities.Build().Capabilities {
		if c.ID == id {
			return &c
		}
	}
	return nil
}

func asStr(args []binding.Value, i int) string {
	if i >= len(args) || args[i] == nil {
		return ""
	}
	if s, ok := args[i].(string); ok {
		return s
	}
	return fmt.Sprintf("%v", args[i])
}
