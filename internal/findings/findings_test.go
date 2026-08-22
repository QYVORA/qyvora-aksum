package findings

import "testing"

func TestIDDeterministicAcrossEvidenceOrder(t *testing.T) {
	a := New("r", "t", "cat", SevLow, ConfObserved).Add("import", "gets", "").Build()
	b := New("r", "t", "cat", SevLow, ConfObserved).Add("string", "0x1000", "").Add("import", "gets", "").Build()
	c := New("r", "t", "cat", SevLow, ConfObserved).Add("import", "gets", "").Add("string", "0x1000", "").Build()
	if b.ID != c.ID {
		t.Fatalf("evidence order changed ID: %s vs %s", b.ID, c.ID)
	}
	if a.ID == b.ID {
		t.Fatal("different evidence must yield different IDs")
	}
}

func TestDedupeMergesAndKeepsBestConfidence(t *testing.T) {
	f1 := New("rule-x", "t", "c", SevMedium, ConfCandidate).Add("import", "gets", "").Build()
	f2 := New("rule-x", "t", "c", SevMedium, ConfValidated).
		Add("import", "gets", "").Add("code", "0x401000", "").Build()
	out := Dedupe([]Finding{f1, f2})
	if len(out) != 1 {
		t.Fatalf("want 1 deduped finding, got %d", len(out))
	}
	if out[0].Confidence != ConfValidated {
		t.Fatalf("confidence should escalate, got %s", out[0].Confidence)
	}
	if len(out[0].Evidence) != 2 {
		t.Fatalf("evidence should merge, got %d", len(out[0].Evidence))
	}
}

func TestDedupeSeverityOrdering(t *testing.T) {
	low := New("a-rule", "t", "c", SevLow, ConfObserved).Build()
	high := New("z-rule", "t", "c", SevHigh, ConfObserved).Build()
	out := Dedupe([]Finding{low, high})
	if out[0].Severity != SevHigh {
		t.Fatalf("high severity must sort first, got %s", out[0].Severity)
	}
}

func TestSeverityRankTotalOrder(t *testing.T) {
	ranks := []Severity{SevInfo, SevLow, SevMedium, SevHigh, SevCritical}
	for i := 1; i < len(ranks); i++ {
		if ranks[i].Rank() <= ranks[i-1].Rank() {
			t.Fatalf("severity order broken at %s", ranks[i])
		}
	}
}
