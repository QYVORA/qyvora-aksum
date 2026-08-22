// Package output renders aksum's human-facing terminal output and its
// machine-readable JSON reports. Terminal lines follow the QYVORA family
// convention:
//
//	[12:41:03] [AKSUM] [PHASE] message
//
// Machine-readable output (--format json) must never be mixed with terminal
// decoration: branding and progress belong to human interfaces only.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Phase names used in the [PHASE] slot.
const (
	PhaseIdentify  = "IDENTIFY"
	PhaseEnum      = "ENUM"
	PhaseAnalysis  = "ANALYSIS"
	PhaseValidate  = "VALIDATE"
	PhaseDynamic   = "DYNAMIC"
	PhaseFindings  = "FINDINGS"
	PhaseReport    = "REPORT"
)

// Printer writes phase-tagged terminal lines. It is safe for concurrent use
// so analysis workers can log without interleaving mid-line.
type Printer struct {
	mu      sync.Mutex
	out     io.Writer
	format  string // "terminal" | "json"
	quiet   bool
	nowFunc func() time.Time
}

// New returns a terminal printer writing to os.Stdout.
func New() *Printer {
	return &Printer{out: os.Stdout, format: "terminal", nowFunc: time.Now}
}

// SetOutput redirects the printer (used by tests).
func (p *Printer) SetOutput(w io.Writer) { p.mu.Lock(); p.out = w; p.mu.Unlock() }

// SetFormat selects terminal or json rendering.
func (p *Printer) SetFormat(f string) { p.mu.Lock(); p.format = f; p.mu.Unlock() }

// Format reports the active format.
func (p *Printer) Format() string { p.mu.Lock(); defer p.mu.Unlock(); return p.format }

// SetQuiet suppresses info-level terminal lines (errors still print).
func (p *Printer) SetQuiet(q bool) { p.mu.Lock(); p.quiet = q; p.mu.Unlock() }

// Info prints one [INFO]-level phase line in terminal mode; no-op in JSON
// mode so structured output stays clean.
func (p *Printer) Info(phase, msg string) {
	p.line("INFO", phase, msg)
}

// Warn prints a warning line.
func (p *Printer) Warn(phase, msg string) {
	p.line("WARN", phase, msg)
}

// Err prints an error line to stderr regardless of quiet.
func (p *Printer) Err(phase, msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(os.Stderr, "%s [AKSUM] [%s] [ERROR] %s\n",
		p.timestamp(), sanitize(phase), sanitize(msg))
}

func (p *Printer) line(level, phase, msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.quiet || p.format != "terminal" {
		return
	}
	fmt.Fprintf(p.out, "%s [AKSUM] [%s] [%s] %s\n",
		p.timestamp(), sanitize(phase), level, sanitize(msg))
}

func (p *Printer) timestamp() string {
	return p.nowFunc().Format("[15:04:05]")
}

// sanitize strips ANSI escape sequences and control characters from
// binary-derived strings before they reach the terminal (spec section 51).
func sanitize(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r < ' ' || r == 0x7f || (r >= 0x80 && r < 0xa0) }) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if r < ' ' || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			b.WriteRune('.')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// EncodeJSON writes v as indented JSON to stdout. In json format this is the
// ONLY thing written to stdout.
func EncodeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
