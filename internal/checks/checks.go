// Package checks implements aksum's static security rules. Each rule
// consumes only verifiable observations (properties, imports, strings,
// segments, cross-references) and reports findings with honest confidence.
// No rule speculates about exploitability it cannot see (spec sections
// 18-21).
package checks

import (
	"fmt"
	"sort"
	"strings"

	strscan "github.com/QYVORA/qyvora-aksum/internal/analysis/strings"
	"github.com/QYVORA/qyvora-aksum/internal/analysis/structure"
	"github.com/QYVORA/qyvora-aksum/internal/binary"
	"github.com/QYVORA/qyvora-aksum/internal/dataflow"
	"github.com/QYVORA/qyvora-aksum/internal/findings"
	"github.com/QYVORA/qyvora-aksum/internal/security/class"
)

// Context bundles everything rules may inspect.
type Context struct {
	Target    *binary.Target
	Imports   []structure.Import
	Segments  []structure.Segment
	Strings   []strscan.Classified
	CallSites []dataflow.CallSite // statically-resolved call sites (may be nil)
}

// Rule is one named check with a stable identifier.
type Rule struct {
	Name string
	Run  func(ctx *Context) ([]findings.Finding, error)
}

var registry []Rule

func register(name string, run func(*Context) ([]findings.Finding, error)) {
	registry = append(registry, Rule{Name: name, Run: run})
}

// All returns the rule registry in deterministic order.
func All() []Rule { return append([]Rule(nil), registry...) }

// Run executes every registered rule and deduplicates results.
func Run(ctx *Context) ([]findings.Finding, error) {
	var out []findings.Finding
	for _, r := range All() {
		fs, err := r.Run(ctx)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.Name, err)
		}
		out = append(out, fs...)
	}
	return findings.Dedupe(out), nil
}

func init() {
	register("hardening-properties", checkHardening)
	register("writable-executable-segment", checkWritableExec)
	register("dangerous-imports", checkDangerousImports)
	register("dangerous-call-sites", checkDangerousCallSites)
	register("weak-crypto-signals", checkWeakCrypto)
	register("sensitive-strings", checkSensitiveStrings)
	register("process-execution-surface", checkProcessExecution)
}

// ---- hardening properties --------------------------------------------

func checkHardening(ctx *Context) ([]findings.Finding, error) {
	var out []findings.Finding
	t := ctx.Target
	if t.Format == binary.FormatRaw {
		return out, nil // no parser: nothing observable, nothing claimed
	}

	prop := func(rule, title string, sev findings.Severity, p binary.Property, desc, validation string) {
		switch p {
		case binary.PropertyDisabled:
			out = append(out, findings.New(rule, title, "hardening", sev, findings.ConfObserved).
				Describe(desc+" Disabling removes a standard mitigation.", "Property read directly from program headers/dynamic entries.",
					validation).Build())
		case binary.PropertyUnknown:
			out = append(out, findings.New(rule, title+" unverifiable", "hardening", findings.SevInfo, findings.ConfSuspected).
				Describe(desc+" The file does not expose enough metadata to determine this property; aksum reports unknown rather than guessing.",
					"Expected metadata absent from the file.",
					validation).Build())
		}
	}
	prop("no-nx", "NX disabled", findings.SevHigh, t.NX,
		"Stack/heap pages are executable.", "Verify segment permissions; re-link with -z noexecstack if confirmed.")
	prop("no-pie", "PIE disabled", findings.SevMedium, t.PIE,
		"Code loads at fixed addresses.", "Check ELF type; re-link with -pie if ASLR is required.")
	if t.RELRO == "none" || (t.RELRO == "" && t.Format == binary.FormatELF) {
		out = append(out, findings.New("no-relro", "RELRO absent", "hardening", findings.SevMedium, findings.ConfObserved).
			Describe("The GOT is writable at runtime, enabling GOT-overwrite techniques.",
				"Dynamic section lacks BIND_NOW and DF_1_NOW.",
				"Re-link with -Wl,-z,relro,-z,now for full RELRO.").Build())
	} else if t.RELRO == "partial" {
		out = append(out, findings.New("partial-relro", "RELRO partial", "hardening", findings.SevLow, findings.ConfObserved).
			Describe(".got.plt remains writable; only part of the GOT is read-only after relocation.",
				"GNU_RELRO segment present without full BIND_NOW semantics.",
				"Add -z now to promote to full RELRO.").Build())
	}
	if t.Canary == binary.PropertyDisabled {
		out = append(out, findings.New("no-canary", "stack canary absent", "hardening", findings.SevMedium, findings.ConfObserved).
			Describe("No __stack_chk_fail-style guard import was found; stack smashing protection appears disabled.",
				"Import table scan for canary runtime symbols.",
				"Rebuild with -fstack-protector-strong.").Build())
	}
	return out, nil
}

// ---- writable + executable segments ----------------------------------

func checkWritableExec(ctx *Context) ([]findings.Finding, error) {
	var out []findings.Finding
	for _, s := range ctx.Segments {
		if strings.ContainsRune(s.Flags, 'w') && strings.ContainsRune(s.Flags, 'x') {
			out = append(out, findings.New("wx-segment",
				fmt.Sprintf("segment %#x is writable and executable", s.VirtualAddr),
				"hardening", findings.SevHigh, findings.ConfObserved).
				Describe("A W+X mapping allows self-modifying code paths and weakens W^X guarantees.",
					fmt.Sprintf("%s segment flags %q (%d bytes).", s.Type, s.Flags, s.FileSize),
					"Confirm the loader actually maps this region W|X; some toolchains declare more than they map.").
				Add("segment", fmt.Sprintf("%#x", s.VirtualAddr), s.Type).Build())
		}
	}
	return out, nil
}

// ---- dangerous imports -------------------------------------------------

// dangerousImports maps libc APIs to the weakness class they indicate.
// Presence alone is CANDIDATE-level: many programs call these safely.
var dangerousImports = []struct {
	symbol string
	title  string
	desc   string
	val    string
}{
	{"gets", "gets() imported", "gets cannot be used safely on unbounded input.", "Remove or replace with fgets."},
	{"strcpy", "strcpy() imported", "No bounds checking on copy destination.", "Prefer strncpy/strlcpy or length-checked copies."},
	{"strcat", "strcat() imported", "Unbounded concatenation can overflow the destination.", "Use strncat/sized appends."},
	{"sprintf", "sprintf() imported", "Unbounded formatted write into a fixed buffer.", "Use snprintf with explicit size."},
	{"vsprintf", "vsprintf() imported", "Unbounded formatted write from varargs.", "Use vsnprintf."},
	{"system", "system() imported", "Shell command execution; command-injection risk when inputs are attacker-influenced.", "Avoid shell invocation or strictly validate input."},
	{"popen", "popen() imported", "Spawns a shell; same injection surface as system().", "Validate inputs or use execve with argv arrays."},
}

func checkDangerousImports(ctx *Context) ([]findings.Finding, error) {
	var out []findings.Finding
	for _, imp := range ctx.Imports {
		for _, d := range dangerousImports {
			if imp.Name != d.symbol {
				continue
			}
			out = append(out, findings.New("dangerous-import-"+d.symbol, d.title,
				"memory-safety", findings.SevMedium, findings.ConfCandidate).
				Describe(d.desc+" Presence is not proof of misuse — review call sites.",
					fmt.Sprintf("Symbol %q present in dynamic import table.", d.symbol),
					d.val).
				Add("import", d.symbol, "").Build())
		}
	}
	return out, nil
}

// ---- dangerous call sites (dataflow-corroborated) -----------------------

// checkDangerousCallSites upgrades dangerous-import reporting when the
// dataflow engine resolved a concrete call site that passes a statically
// known string to the risky API. Reachability plus argument data moves the
// finding from CANDIDATE (mere presence) to VALIDATED with code evidence.
func checkDangerousCallSites(ctx *Context) ([]findings.Finding, error) {
	var out []findings.Finding
	for _, d := range dangerousImports {
		for _, site := range ctx.CallSites {
			if site.Callee != d.symbol {
				continue
			}
			arg := ""
			for _, a := range site.Args {
				if a.Kind == dataflow.KindString && len(a.Text) > len(arg) {
					arg = a.Text
				}
			}
			if arg == "" {
				continue // presence-level evidence is covered by dangerous-imports
			}
			out = append(out, findings.New("dangerous-call-"+d.symbol,
				fmt.Sprintf("%s() called with static string %q", d.symbol, truncateStr(arg, 48)),
				"memory-safety", findings.SevHigh, findings.ConfValidated).
				Describe(d.desc+" The call site was resolved by intra-procedural dataflow; the argument value is fixed in the binary.",
					fmt.Sprintf("%s (at %#x) calls %s with statically-resolved argument %q.",
						site.Caller, site.Addr, d.symbol, truncateStr(arg, 64)),
					"Confirm the argument source is not attacker-influenced at runtime.").
				Add("import", d.symbol, "").
				Add("callsite", fmt.Sprintf("%#x", site.Addr),
					fmt.Sprintf("caller=%s", site.Caller)).
				Add("string", fmt.Sprintf("%q", arg), "").Build())
		}
	}
	return out, nil
}

// ---- weak / legacy crypto signals --------------------------------------
var weakCryptoMarkers = []struct {
	token string
	note  string
}{
	{"md5", "MD5 is cryptographically broken for collision resistance."},
	{"sha1", "SHA-1 collision attacks are practical."},
	{"des", "DES has a 56-bit key and is deprecated."},
	{"rc4", "RC4 is broken and prohibited by RFC 7465 in TLS."},
	{"ecb", "ECB mode leaks plaintext structure."},
}

func checkWeakCrypto(ctx *Context) ([]findings.Finding, error) {
	var out []findings.Finding
	seen := map[string]bool{}
	for _, s := range ctx.Strings {
		low := strings.ToLower(s.Value)
		for _, m := range weakCryptoMarkers {
			if seen[m.token] || !strings.Contains(low, m.token) {
				continue
			}
			seen[m.token] = true
			loc := s.Section
			if s.Address != 0 {
				loc = fmt.Sprintf("%#x", s.Address)
			}
			out = append(out, findings.New("weak-crypto-"+m.token, "possible "+strings.ToUpper(m.token)+" usage", "crypto", findings.SevLow, findings.ConfSuspected).
				Describe(m.note+" This is a string-level signal only; the algorithm may be referenced but unused, or the token may be incidental.",
					fmt.Sprintf("String match %q at %s.", truncateStr(s.Value, 48), loc),
					"Confirm via code cross-references before treating as real usage.").
				Add("string", loc, truncateStr(s.Value, 64)).Build())
		}
	}
	return out, nil
}

// ---- sensitive strings ---------------------------------------------------

var sensitiveMarkers = []struct {
	token string
	title string
}{
	{"password", "password-related string"},
	{"private key", "embedded private-key marker"},
	{"begin rsa private key", "RSA private key PEM header"},
	{"api_key", "API key naming pattern"},
	{"secret", "secret-naming pattern"},
}

func checkSensitiveStrings(ctx *Context) ([]findings.Finding, error) {
	counts := map[string]int{}
	var firstLoc = map[string]string{}
	for _, s := range ctx.Strings {
		low := strings.ToLower(s.Value)
		for _, m := range sensitiveMarkers {
			if !strings.Contains(low, m.token) {
				continue
			}
			counts[m.title]++
			if counts[m.title] == 1 {
				loc := s.Section
				if s.Address != 0 {
					loc = fmt.Sprintf("%#x", s.Address)
				}
				firstLoc[m.title] = loc
			}
			break
		}
	}
	titles := make([]string, 0, len(counts))
	for t := range counts {
		titles = append(titles, t)
	}
	sort.Strings(titles)
	out := make([]findings.Finding, 0, len(titles))
	for _, t := range titles {
		b := findings.New("sensitive-string", "embedded "+t+" ("+fmt.Sprint(counts[t])+" match(es))",
			"secrets", findings.SevLow, findings.ConfSuspected).
			Describe("Naming suggests credentials or secrets may be embedded. Matches are often benign format strings or help text.",
				fmt.Sprintf("%d string(s) matched sensitive markers.", counts[t]),
				"Inspect matches manually; rotate any real credential found.")
		b.Add("string", firstLoc[t], "")
		out = append(out, b.Build())
	}
	return out, nil
}

// ---- process execution surface ------------------------------------------

func checkProcessExecution(ctx *Context) ([]findings.Finding, error) {
	hits := make([]string, 0, 4)
	for _, imp := range ctx.Imports {
		if cat := class.Category(imp.Name); cat == class.CatExec {
			hits = append(hits, imp.Name)
		}
	}
	if len(hits) == 0 {
		return nil, nil
	}
	sort.Strings(hits)
	b := findings.New("execution-surface", "process-execution API surface",
		"attack-surface", findings.SevInfo, findings.ConfObserved).
		Describe("The binary imports process-spawning APIs. This expands attack surface when inputs reach these calls.",
			fmt.Sprintf("Imported: %s.", strings.Join(hits, ", ")),
			"Trace argument construction for injection potential.")
	for _, h := range hits {
		b.Add("import", h, "")
	}
	return []findings.Finding{b.Build()}, nil
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "~"
}
