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

// Rank exposes confidence ordering for external passes (validation).
func (c Confidence) Rank() int { return confRank[c] }

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

// Dedupe groups findings sharing a rule whose evidence overlaps (same rule,
// same observation) into one record, keeping the highest confidence and
// unioning evidence. Grouping is order-independent: it depends only on the
// rule/location relation structure, so repeated runs produce identical IDs.
func Dedupe(all []Finding) []Finding {
	// Bucket by rule, then connect components through shared locations.
	type bucket struct {
		locOwner map[string]int // location -> component index
		comps    [][]Finding
	}
	buckets := map[string]*bucket{}
	for _, f := range all {
		b := buckets[f.Rule]
		if b == nil {
			b = &bucket{locOwner: map[string]int{}}
			buckets[f.Rule] = b
		}
		locs := locations(f)
		ci := -1
		for _, l := range locs {
			if owner, ok := b.locOwner[l]; ok {
				ci = owner
				break
			}
		}
		if ci < 0 {
			b.comps = append(b.comps, nil)
			ci = len(b.comps) - 1
		}
		b.comps[ci] = append(b.comps[ci], f)
		for _, l := range locs {
			b.locOwner[l] = ci
		}
	}

	var out []Finding
	for _, rule := range sortedKeys(buckets) {
		b := buckets[rule]
		for _, comp := range b.comps {
			merged := comp[0]
			seen := map[string]bool{}
			for i := 1; i < len(comp); i++ {
				if confRank[comp[i].Confidence] > confRank[merged.Confidence] {
					merged.Confidence = comp[i].Confidence
				}
				merged.Evidence = append(merged.Evidence, comp[i].Evidence...)
			}
			var uniq []Evidence
			for _, e := range merged.Evidence {
				k := e.Kind + "@" + e.Location + "\x00" + e.Detail
				if !seen[k] {
					seen[k] = true
					uniq = append(uniq, e)
				}
			}
			merged.Evidence = uniq
			out = append(out, merged)
		}
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

func locations(f Finding) []string {
	locs := make([]string, 0, len(f.Evidence))
	for _, e := range f.Evidence {
		locs = append(locs, e.Kind+"@"+e.Location)
	}
	sort.Strings(locs)
	return locs
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
