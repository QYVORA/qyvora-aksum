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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// SchemaVersion is the event schema version every emitted event carries.
const SchemaVersion = "1.0"

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

	BinaryIdentified     = "binary.identified"
	FunctionDiscovered   = "function.discovered"
	StringDiscovered     = "string.discovered"
	CandidateFound       = "candidate.found"
	ValidationStarted    = "validation.started"
	ValidationCompleted  = "validation.completed"
)

// Level values for the envelope's level field.
const (
	LevelInfo    = "info"
	LevelWarning = "warning"
	LevelError   = "error"
)

// Event is the wire shape of one event line.
type Event struct {
	SchemaVersion string         `json:"schema_version"`
	Timestamp     time.Time      `json:"timestamp"`
	ExecutionID   string         `json:"execution_id"`
	Framework     string         `json:"framework"`
	Level         string         `json:"level"`
	Event         string         `json:"event"`
	Data          map[string]any `json:"data,omitempty"`
}

// Stream writes events as JSONL to w. It is safe for concurrent use.
type Stream struct {
	mu          sync.Mutex
	w           io.Writer
	executionID string
}

// NewStream returns a stream bound to a freshly generated execution id.
func NewStream(w io.Writer) *Stream {
	return &Stream{w: w, executionID: newExecutionID()}
}

// Emit writes one event. Data may be nil.
func (s *Stream) Emit(level, name string, data map[string]any) {
	if s == nil || s.w == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ev := Event{
		SchemaVersion: SchemaVersion,
		Timestamp:     time.Now().UTC(),
		ExecutionID:   s.executionID,
		Framework:     "aksum",
		Level:         level,
		Event:         name,
		Data:          data,
	}
	enc := json.NewEncoder(s.w)
	if err := enc.Encode(ev); err != nil {
		return // stream closed or unwritable; nothing sensible left to do
	}
}

func newExecutionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "aksum-" + time.Now().UTC().Format("20060102T150405.000000000")
	}
	return hex.EncodeToString(b[:])
}
