// Package findings defines the aksum finding model: explicit confidence
// states, evidence records, and deterministic identity for deduplication
// (spec sections 19-21). A finding never claims more than its evidence
// supports; the confidence vocabulary makes that constraint machine-checkable.
package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Confidence is the epistemic state of a finding (spec section 20):
//
//	OBSERVED   directly read from the binary (property, import presence)
//	CANDIDATE  concrete signal needing review (dangerous import present)
//	SUSPECTED  pattern match that may be incidental (weak-crypto string)
//	VALIDATED  corroborated by >= 2 independent signals
//	CONFIRMED  dynamically exercised (future stage)
type Confidence string

const (
	ConfObserved  Confidence = "OBSERVED"
	ConfCandidate Confidence = "CANDIDATE"
	ConfSuspected Confidence = "SUSPECTED"
	ConfValidated Confidence = "VALIDATED"
	ConfConfirmed Confidence = "CONFIRMED"
)

var confRank = map[Confidence]int{
	ConfSuspected: 1, ConfCandidate: 2, ConfObserved: 2, ConfValidated: 3, ConfConfirmed: 4,
}

// Severity rates potential impact if the weakness is real.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

var sevRank = map[Severity]int{
	SevInfo: 0, SevLow: 1, SevMedium: 2, SevHigh: 3, SevCritical: 4,
}

// Rank exposes ordering for external sorting/reporting.
func (s Severity) Rank() int { return sevRank[s] }

// Evidence is one verifiable observation backing a finding.
type Evidence struct {
	Kind     string `json:"kind"`             // property|import|string|code|xref|segment
	Location string `json:"location"`         // address, section, symbol, or flag name
	Detail   string `json:"detail,omitempty"` // sanitized human context
}

// Finding is one reported weakness or observation.
type Finding struct {
	ID          string     `json:"id"`
	Rule        string     `json:"rule"`
	Title       string     `json:"title"`
	Category    string     `json:"category"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Description string     `json:"description"`
	Reason      string     `json:"detection_reason"`
	Validation  string     `json:"validation"`
	Evidence    []Evidence `json:"evidence"`
}

// Builder incrementally assembles a finding and computes its stable ID.
type Builder struct {
	f Finding
}

// New starts a finding for the given rule.
func New(rule, title, category string, sev Severity, conf Confidence) *Builder {
	return &Builder{f: Finding{
		Rule: rule, Title: title, Category: category,
		Severity: sev, Confidence: conf,
	}}
}

// Describe sets description, detection reason, and validation guidance.
func (b *Builder) Describe(desc, reason, validation string) *Builder {
	b.f.Description, b.f.Reason, b.f.Validation = desc, reason, validation
	return b
}

// Add appends an evidence record.
func (b *Builder) Add(kind, location, detail string) *Builder {
	b.f.Evidence = append(b.f.Evidence, Evidence{Kind: kind, Location: location, Detail: detail})
	return b
}

// Build finalizes the finding, computing ID from rule + sorted evidence
// locations so identical observations across runs deduplicate to one ID.
func (b *Builder) Build() Finding {
	locs := make([]string, 0, len(b.f.Evidence))
	for _, e := range b.f.Evidence {
		locs = append(locs, e.Kind+"@"+e.Location)
	}
	sort.Strings(locs)
	h := sha256.Sum256([]byte(b.f.Rule + "\x00" + strings.Join(locs, "|")))
	prefix := strings.ToUpper(strings.ReplaceAll(b.f.Category, "-", "") + "XXXXXX")
	b.f.ID = fmt.Sprintf("AKS-%s-%s", prefix[:6], hex.EncodeToString(h[:])[:8])
	if b.f.Evidence == nil {
		b.f.Evidence = []Evidence{}
	}
	return b.f
}

// Dedupe collapses findings sharing a rule and evidence signature, keeping
// the highest-confidence instance and merging evidence.
func Dedupe(all []Finding) []Finding {
	type key struct {
		rule  string
		idSig string
	}
	byKey := map[key]*Finding{}
	var order []key
	for i := range all {
		f := all[i]
		locs := make([]string, 0, len(f.Evidence))
		for _, e := range f.Evidence {
			locs = append(locs, e.Kind+"@"+e.Location)
		}
		sort.Strings(locs)
		k := key{f.Rule, strings.Join(locs, "|")}
		existing, ok := byKey[k]
		if !ok {
			cp := f
			byKey[k] = &cp
			order = append(order, k)
			continue
		}
		if confRank[f.Confidence] > confRank[existing.Confidence] {
			existing.Confidence = f.Confidence
		}
		for _, e := range f.Evidence {
			dup := false
			for _, ex := range existing.Evidence {
				if ex.Kind == e.Kind && ex.Location == e.Location && ex.Detail == e.Detail {
					dup = true
					break
				}
			}
			if !dup {
				existing.Evidence = append(existing.Evidence, e)
			}
		}
	}
	out := make([]Finding, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	// Deterministic presentation order: severity desc, then rule, then ID.
	sort.Slice(out, func(i, j int) bool {
		si, sj := out[i].Severity.Rank(), out[j].Severity.Rank()
		if si != sj {
			return si > sj
		}
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		return out[i].ID < out[j].ID
	})
	return out
}
