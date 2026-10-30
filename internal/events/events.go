// Package events implements the shared QYVORA JSONL event envelope used by
// anansi, toha3ee and jabari. Every emitted line is one JSON object:
//
//	{"schema_version":"1.0","timestamp":"...","execution_id":"...",
//	 "framework":"aksum","level":"info","event":"scan.started","data":{}}
//
// Consumers key on event names, never on terminal output. See
// QYVORA-TOOL-OUTPUT-SPEC.md section 2 for the frozen contract.
package events

import (
	"io"

	shared "github.com/QYVORA/qyvora-events"
)

// SchemaVersion is the event schema version every emitted event carries.
const SchemaVersion = shared.SchemaVersion

// Event names. Shared verbs use the ecosystem spelling exactly; aksum adds
// binary-analysis-specific verbs prefixed with "binary." / "function." /
// "candidate." so consumers can route on prefix without a lookup table.
const (
	ScanStarted       = "scan.started"
	ScanCompleted     = "scan.completed"
	PhaseStarted      = "phase.started"
	PhaseCompleted    = "phase.completed"
	FindingDiscovered = "finding.discovered"
	Warning           = "warning"
	Error             = "error"
	ReportGenerated   = "report.generated"

	BinaryIdentified    = "binary.identified"
	FunctionDiscovered  = "function.discovered"
	StringDiscovered    = "string.discovered"
	CandidateFound      = "candidate.found"
	ValidationStarted   = "validation.started"
	ValidationCompleted = "validation.completed"
)

// Level values for the envelope's level field.
const (
	LevelInfo    = shared.LevelInfo
	LevelWarning = shared.LevelWarning
	LevelError   = shared.LevelError
)

type Event = shared.Event
type Stream = shared.Stream

// NewStream returns a stream bound to aksum.
func NewStream(w io.Writer) *Stream { return shared.NewStream(w, "aksum") }
