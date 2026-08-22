// Package dynamic defines the architecture for dynamic analysis: an
// execution plan format, a safety policy every backend must honor, and the
// Sandbox interface backends implement.
//
// This build ships NO execution backend. The only provided implementation
// is PlanOnlyBackend, which produces and validates plans but refuses to
// execute anything. That is deliberate honesty, not a stub left by
// accident: running untrusted binaries requires a real isolation boundary
// (namespace/container sandbox with seccomp profile), and pretending to
// have one would be worse than not having one.
//
// A future backend must:
//   - treat Plan as the sole description of what may run;
//   - enforce Policy mechanically (timeout, no network unless explicitly
//     allowed, output caps), not by convention;
//   - refuse targets whose identification is unknown (RAW files);
//   - report Result with exit status and bounded output, feeding the
//     findings pipeline CONFIRMED confidence states.
package dynamic

import (
	"errors"
	"fmt"
	"time"

	"github.com/QYVORA/qyvora-aksum/internal/binary"
)

// SchemaVersion is the plan/result envelope version.
const SchemaVersion = "1.0"

// ErrBackendUnavailable is returned by backends that cannot execute in
// this build. errors.Is-compatible.
var ErrBackendUnavailable = errors.New("no dynamic-execution backend is bundled with this build")

// Policy bounds everything a backend may do. Zero-value fields are replaced
// by Defaults; explicit values are validated by BuildPlan.
type Policy struct {
	Timeout          time.Duration `json:"timeout"`           // wall-clock cap per run
	AllowNetwork     bool          `json:"allow_network"`     // default false: no egress
	AllowFileWrite   bool          `json:"allow_file_write"`  // writes outside scratch dir
	MaxOutputBytes   int           `json:"max_output_bytes"`  // captured stdout+stderr cap
	ConsentConfirmed bool          `json:"consent_confirmed"` // operator explicitly accepted execution risk
}

// Defaults returns the conservative policy.
func Defaults() Policy {
	return Policy{
		Timeout:        5 * time.Second,
		AllowNetwork:   false,
		AllowFileWrite: false,
		MaxOutputBytes: 1 << 20, // 1 MiB
	}
}

const (
	maxTimeout       = 5 * time.Minute
	minOutput        = 1 << 10 // 1 KiB floor keeps results meaningful
	maxOutputCap int = 64 << 20
)

// Validate enforces mechanical safety bounds.
func (p Policy) Validate() error {
	if p.Timeout <= 0 || p.Timeout > maxTimeout {
		return fmt.Errorf("policy timeout %s outside (0, %s]", p.Timeout, maxTimeout)
	}
	if p.MaxOutputBytes < minOutput || p.MaxOutputBytes > maxOutputCap {
		return fmt.Errorf("policy max_output_bytes %d outside [%d, %d]",
			p.MaxOutputBytes, minOutput, maxOutputCap)
	}
	if !p.ConsentConfirmed {
		return fmt.Errorf("execution consent not confirmed")
	}
	return nil
}

// Plan is the complete, auditable description of one proposed run.
type Plan struct {
	Framework string     `json:"framework"` // "aksum"
	Schema    string     `json:"schema_version"`
	Target    PlanTarget `json:"target"`
	Args      []string   `json:"args,omitempty"`
	Policy    Policy     `json:"policy"`
	Rationale string     `json:"rationale"`
	CreatedAt time.Time  `json:"created_at"`
}

// PlanTarget identifies what would run.
type PlanTarget struct {
	Path   string        `json:"path"`
	Format binary.Format `json:"format"`
	Arch   binary.Arch   `json:"arch"`
	SHA256 string        `json:"sha256,omitempty"`
}

// Session is an opaque handle a backend hands out after Prepare.
type Session struct {
	ID   string `json:"id"`
	Plan *Plan  `json:"-"`
}

// Result is what a real backend reports after a run.
type Result struct {
	SessionID  string        `json:"session_id"`
	ExitCode   int           `json:"exit_code"`
	Duration   time.Duration `json:"duration"`
	OutputTail string        `json:"output_tail,omitempty"` // sanitized, capped
	TimedOut   bool          `json:"timed_out"`
}

// Sandbox is the contract any execution backend implements.
type Sandbox interface {
	Name() string
	Capabilities() []string
	Prepare(plan *Plan) (*Session, error)
	Run(session *Session) (*Result, error)
}

// BuildPlan validates inputs and policy, refusing anything that cannot be
// described honestly. RAW-format targets are rejected: aksum could not
// identify them, so it cannot claim to know what would execute.
func BuildPlan(target *binary.Target, args []string, pol Policy) (*Plan, error) {
	if target == nil {
		return nil, fmt.Errorf("nil target")
	}
	if target.Format == binary.FormatRaw {
		return nil, fmt.Errorf("%s: format %q is unidentified; refusing to plan execution of unknown content",
			target.Path, target.Format)
	}
	if !pol.ConsentConfirmed {
		return nil, fmt.Errorf("dynamic analysis executes the target; pass explicit consent to plan it")
	}
	if err := pol.Validate(); err != nil {
		return nil, err
	}
	return &Plan{
		Framework: "aksum",
		Schema:    SchemaVersion,
		Target: PlanTarget{
			Path:   target.Path,
			Format: target.Format,
			Arch:   target.Arch,
			SHA256: target.SHA256,
		},
		Args:      append([]string(nil), args...),
		Policy:    pol,
		Rationale: "operator-requested dynamic validation of static findings",
		CreatedAt: time.Now().UTC(),
	}, nil
}

// PlanOnlyBackend validates plans but never executes. Prepare fails with
// ErrBackendUnavailable after full plan validation, so operators get every
// safety check plus an honest refusal in one step.
type PlanOnlyBackend struct{}

var _ Sandbox = PlanOnlyBackend{}

func (PlanOnlyBackend) Name() string { return "plan-only" }

func (PlanOnlyBackend) Capabilities() []string {
	return []string{"plan-validation", "policy-enforcement", "no-execution"}
}

func (PlanOnlyBackend) Prepare(plan *Plan) (*Session, error) {
	if plan == nil {
		return nil, fmt.Errorf("nil plan")
	}
	if err := plan.Policy.Validate(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w: plan for %s validated OK (%s policy); execution requires a sandbox backend",
		ErrBackendUnavailable, plan.Target.Path, plan.Policy.Timeout)
}

func (PlanOnlyBackend) Run(*Session) (*Result, error) {
	return nil, ErrBackendUnavailable
}
