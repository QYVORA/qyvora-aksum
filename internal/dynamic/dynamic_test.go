package dynamic

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-aksum/internal/binary"
)

func elfTarget() *binary.Target {
	return &binary.Target{
		Path:   "/tmp/sample",
		Format: binary.FormatELF,
		Arch:   "x86-64",
		SHA256: "abc123",
	}
}

func consenting() Policy {
	p := Defaults()
	p.ConsentConfirmed = true
	return p
}

func TestBuildPlanHappyPath(t *testing.T) {
	plan, err := BuildPlan(elfTarget(), []string{"--serve"}, consenting())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Framework != "aksum" || plan.Schema != SchemaVersion {
		t.Errorf("envelope wrong: %+v", plan)
	}
	if plan.Target.Format != binary.FormatELF || plan.Target.SHA256 == "" {
		t.Errorf("target not carried: %+v", plan.Target)
	}
	if plan.Policy.AllowNetwork {
		t.Errorf("default policy must not allow network")
	}
}

func TestBuildPlanRefusals(t *testing.T) {
	raw := &binary.Target{Path: "/tmp/x", Format: binary.FormatRaw, Arch: "unknown"}

	if _, err := BuildPlan(raw, nil, consenting()); err == nil {
		t.Error("RAW target must be refused")
	} else {
		// The retry-relevant detail is the format: the refusal must name the
		// unidentified container so an operator knows why planning stopped.
		if !strings.Contains(err.Error(), `"RAW"`) && !strings.Contains(err.Error(), "unidentified") {
			t.Fatalf("refusal must identify the RAW cause, got: %v", err)
		}
	}

	if _, err := BuildPlan(elfTarget(), nil, Defaults()); err == nil {
		t.Error("missing consent must be refused")
	}

	noisy := consenting()
	noisy.Timeout = time.Hour
	if _, err := BuildPlan(elfTarget(), nil, noisy); err == nil {
		t.Error("excessive timeout must be refused")
	}

	greedy := consenting()
	greedy.MaxOutputBytes = 1 << 30
	if _, err := BuildPlan(elfTarget(), nil, greedy); err == nil {
		t.Error("oversized output cap must be refused")
	}
}

func TestPlanOnlyBackendValidatesThenRefuses(t *testing.T) {
	var b Sandbox = PlanOnlyBackend{}
	if b.Name() != "plan-only" {
		t.Errorf("name = %q", b.Name())
	}
	caps := b.Capabilities()
	if len(caps) == 0 || caps[len(caps)-1] != "no-execution" {
		t.Errorf("capabilities must state no-execution: %v", caps)
	}

	bad := &Plan{Framework: "aksum", Schema: SchemaVersion, Policy: Defaults()}
	if _, err := b.Prepare(bad); err == nil {
		t.Fatal("plan without consent must fail validation")
	}

	plan, err := BuildPlan(elfTarget(), nil, consenting())
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.Prepare(plan)
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("Prepare err = %v, want ErrBackendUnavailable", err)
	}

	_, err = b.Run(&Session{ID: "s1", Plan: plan})
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("Run err = %v, want ErrBackendUnavailable", err)
	}
}

func TestDefaultsAreConservative(t *testing.T) {
	d := Defaults()
	if d.AllowNetwork || d.AllowFileWrite {
		t.Errorf("defaults loosened: %+v", d)
	}
	if d.Timeout <= 0 || d.Timeout > 30*time.Second {
		t.Errorf("default timeout %s suspicious", d.Timeout)
	}
}
