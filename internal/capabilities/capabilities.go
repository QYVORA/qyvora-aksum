// Package capabilities exposes the machine-readable tool contract so
// automation and humans can read what this framework actually implements,
// without trusting prose.
package capabilities

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/QYVORA/qyvora-aksum/internal/events"
	"github.com/QYVORA/qyvora-aksum/internal/version"
)

// Command describes one CLI command surface.
type Command struct {
	Name        string   `json:"name"`
	Summary     string   `json:"summary"`
	OutputModes []string `json:"output_modes"`
}

// Capability lists one implemented capability area.
type Capability struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Implemented bool   `json:"implemented"`
	Arch        string `json:"arch,omitempty"` // architecture scope (e.g. "x86/x86-64")
	Note        string `json:"note,omitempty"`
}

// Document is the full machine-readable contract of this framework build.
type Document struct {
	Framework      string         `json:"framework"`
	Version        string         `json:"version"`
	ExitCodes      map[string]int `json:"exit_codes"`
	OutputFormats  []string       `json:"output_formats"`
	EventVerbs     []string       `json:"event_verbs"`
	SeverityLevels []string       `json:"severity_levels"`
	Confidence     []string       `json:"confidence_levels"`
	Authorized     string         `json:"authorization_model"`
	Capabilities   []Capability   `json:"capabilities"`
	Commands       []Command      `json:"commands"`
}

// Build assembles the capability document for this build.
func Build() Document {
	return Document{
		Framework: version.Framework,
		Version:   version.Version,
		ExitCodes: map[string]int{
			"success": 0, "runtime": 1, "usage": 2, "unsupported": 3, "interrupted": 130,
		},
		OutputFormats: []string{"terminal", "json"},
		EventVerbs: []string{
			events.ScanStarted, events.ScanCompleted,
			events.PhaseStarted, events.PhaseCompleted,
			events.FindingDiscovered, events.BinaryIdentified,
			events.FunctionDiscovered, events.StringDiscovered,
			events.CandidateFound, events.ValidationStarted,
			events.ValidationCompleted, events.ReportGenerated,
			events.Warning, events.Error,
		},
		SeverityLevels: []string{
			"critical", "high", "medium", "low", "informational",
		},
		Confidence: []string{
			"confirmed", "high", "medium", "low", "unknown",
		},
		Authorized: "offline binary analysis requires no authorization; " +
			"dynamic analysis requires explicit --authorized flag for live execution",
		Capabilities: []Capability{
			{ID: "binary.identification", Name: "binary format identification", Implemented: true},
			{ID: "binary.enumeration", Name: "section/segment/import enumeration", Implemented: true},
			{ID: "binary.symbols", Name: "symbol table analysis", Implemented: true},
			{ID: "disasm.static", Name: "static disassembly", Implemented: true, Arch: "x86/x86-64"},
			{ID: "disasm.linear", Name: "linear sweep disassembly", Implemented: true, Arch: "x86/x86-64"},
			{ID: "disasm.recursive", Name: "recursive descent disassembly", Implemented: true, Arch: "x86/x86-64"},
			{ID: "analysis.strings", Name: "strings extraction & analysis", Implemented: true},
			{ID: "analysis.functions", Name: "function discovery & analysis", Implemented: true, Arch: "x86/x86-64"},
			{ID: "analysis.dataflow", Name: "dataflow analysis", Implemented: true, Arch: "x86/x86-64"},
			{ID: "analysis.xrefs", Name: "cross-reference analysis", Implemented: true, Arch: "x86/x86-64"},
			{ID: "cfg.build", Name: "control flow graph construction", Implemented: true, Arch: "x86/x86-64"},
			{ID: "surface.api", Name: "API surface mapping", Implemented: true},
			{ID: "security.checks", Name: "security hardening checks", Implemented: true},
			{ID: "security.weaknesses", Name: "candidate weakness identification", Implemented: true},
			{ID: "dynamic.execution", Name: "live dynamic analysis", Implemented: false,
				Note: "dynamic instrumentation planned but not yet implemented"},
			{ID: "formats.elf", Name: "ELF format support", Implemented: true},
			{ID: "formats.pe", Name: "PE/COFF format support", Implemented: false,
				Note: "PE support documented but not yet implemented"},
			{ID: "formats.macho", Name: "Mach-O format support", Implemented: false,
				Note: "Mach-O support documented but not yet implemented"},
			{ID: "arch.x86", Name: "x86 architecture support", Implemented: true},
			{ID: "arch.x86_64", Name: "x86-64 architecture support", Implemented: true},
			{ID: "arch.arm64", Name: "ARM64 architecture support", Implemented: false,
				Note: "ARM64 support documented but not yet implemented"},
		},
		Commands: []Command{
			{Name: "analyze", Summary: "run full security assessment on a binary", OutputModes: []string{"terminal", "json"}},
			{Name: "identify", Summary: "identify binary format and architecture", OutputModes: []string{"terminal", "json"}},
			{Name: "strings", Summary: "extract and analyze strings", OutputModes: []string{"terminal", "json"}},
			{Name: "functions", Summary: "discover and list functions", OutputModes: []string{"terminal", "json"}},
			{Name: "xrefs", Summary: "show cross-references", OutputModes: []string{"terminal", "json"}},
			{Name: "disasm", Summary: "disassemble code", OutputModes: []string{"terminal", "json"}},
			{Name: "dynamic", Summary: "run authorized dynamic analysis", OutputModes: []string{"terminal", "json"}},
			{Name: "target", Summary: "manage assessment target", OutputModes: []string{"terminal", "json"}},
			{Name: "capabilities", Summary: "print this machine-readable contract", OutputModes: []string{"terminal", "json"}},
		},
	}
}

// RenderJSON returns the document as JSON.
func RenderJSON() ([]byte, error) {
	doc := Build()
	SortCapabilities(&doc)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding capabilities: %w", err)
	}
	return data, nil
}

// RenderTable returns capability rows for terminal table rendering.
func RenderTable() [][]string {
	doc := Build()
	SortCapabilities(&doc)
	rows := make([][]string, 0, len(doc.Capabilities))
	for _, c := range doc.Capabilities {
		impl := "yes"
		if !c.Implemented {
			impl = "no"
		}
		note := c.Note
		if c.Arch != "" {
			if note != "" {
				note = c.Arch + "; " + note
			} else {
				note = c.Arch
			}
		}
		rows = append(rows, []string{c.ID, c.Name, impl, note})
	}
	return rows
}

// RenderCommands returns command rows for terminal table rendering.
func RenderCommands() [][]string {
	doc := Build()
	rows := make([][]string, 0, len(doc.Commands))
	for _, c := range doc.Commands {
		rows = append(rows, []string{c.Name, c.Summary, strings.Join(c.OutputModes, ",")})
	}
	return rows
}

// SortCapabilities orders capabilities by ID for deterministic output.
func SortCapabilities(doc *Document) {
	sort.Slice(doc.Capabilities, func(i, j int) bool {
		return doc.Capabilities[i].ID < doc.Capabilities[j].ID
	})
}
