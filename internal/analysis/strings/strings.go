// Package strings implements aksum's string-analysis engine: extraction of
// printable runs from loadable/allocated sections plus security-relevant
// classification with explicit confidence.
//
// Classification philosophy: a match is an OBSERVATION, not a finding.
// The literal "password" in .rodata is not proof of a credential — every
// classified string carries a confidence level and consumers must treat
// low-confidence classes as leads only (spec section 9).
package strings

import (
	"debug/elf"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Confidence levels for string classification.
const (
	ConfHigh   = "high"
	ConfMedium = "medium"
	ConfLow    = "low"
)

// Class names for security-relevant strings.
const (
	ClassURL          = "url"
	ClassIP           = "ip_address"
	ClassFilePath     = "file_path"
	ClassCommand      = "command_like"
	ClassSQL          = "sql_fragment"
	ClassAuthKeyword  = "auth_keyword"
	ClassEnvVar       = "env_var_reference"
	ClassPotentialKey = "potential_secret"
	ClassCrypto       = "crypto_indicator"
)

// Str is one extracted string with its location.
type Str struct {
	Value    string `json:"value"`
	Offset   uint64 `json:"offset"`  // file offset
	Address  uint64 `json:"address"` // virtual address when mapped
	Section  string `json:"section"`
	Length   int    `json:"length"`   // bytes
	Encoding string `json:"encoding"` // ascii | utf8 | utf16le
}

// Classified is a string plus its security-relevant classification, if any.
type Classified struct {
	Str
	Class      string `json:"class,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

// Options bound the scan (resource limits; spec section 49).
type Options struct {
	MinLength  int // minimum printable run to report
	MaxStrings int // hard cap on reported strings (0 = unlimited)
	UTF16      bool
}

var (
	reURL    = regexp.MustCompile(`(?:https?|ftp|wss?)://[^\s\x00"'<>]{4,}`)
	reIPv4   = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	rePath   = regexp.MustCompile(`(?:/[A-Za-z0-9._\-]{2,}){2,}|\b(?:etc|usr|bin|sbin|var|tmp|home|proc|sys)(?:/[A-Za-z0-9._\-]+)+`)
	reCmd    = regexp.MustCompile(`\b(?:/bin/(?:sh|bash)|sh -c|system\s*\(|popen\s*\(|cmd\.exe)\b`)
	reSQL    = regexp.MustCompile(`(?i)\b(?:select\s+.+\s+from\s+|insert\s+into\s+|update\s+\w+\s+set\s+|delete\s+from\s+)\b`)
	reAuth   = regexp.MustCompile(`(?i)^(?:pass(word)?|passwd|user(name)?|login|token|secret|api[-_]?key|auth)`)
	reEnv    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,}$`)
	reKey    = regexp.MustCompile(`(?i)(?:BEGIN (?:RSA )?PRIVATE KEY|(?:sk|pk)_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})`)
	reCrypto = regexp.MustCompile(`(?i)\b(aes|rsa|ecdsa|ed25519|sha1|sha256|sha512|md5|hmac|blowfish|chacha20|curve25519)(?:[-_ ]?(?:128|192|256|key|cert|sign))?`)
)

// Extract walks allocated, non-executable sections and returns printable
// strings. Executable code is skipped by default: instruction bytes produce
// noise strings that pollute classification; callers wanting them can pass
// IncludeCode via options in a later revision.
func Extract(f *elf.File, opts Options) []Str {
	if opts.MinLength < 4 {
		opts.MinLength = 4
	}
	var out []Str
	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_PROGBITS || sec.Size == 0 {
			continue
		}
		// Skip code sections by default: instruction bytes produce
		// printable runs ("AWAVAUAT") that pollute classification.
		if sec.Flags&elf.SHF_EXECINSTR != 0 {
			continue
		}
		if sec.Flags&elf.SHF_ALLOC == 0 && sec.Name != ".rodata" && sec.Name != ".comment" {
			continue
		}
		if sec.Size > 256<<20 { // refuse absurd single-section scans
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		out = append(out, extractASCII(data, uint64(sec.Offset), sec.Addr, sec.Name, opts.MinLength)...)
		if opts.UTF16 {
			out = append(out, extractUTF16LE(data, uint64(sec.Offset), sec.Addr, sec.Name, opts.MinLength)...)
		}
	}
	if opts.MaxStrings > 0 && len(out) > opts.MaxStrings {
		out = out[:opts.MaxStrings]
	}
	return out
}

func extractASCII(data []byte, fileOff, vaddr uint64, section string, minLen int) []Str {
	var out []Str
	start := -1
	flush := func(end int) {
		n := end - start
		if n >= minLen {
			v := sanitizeRun(data[start:end])
			if utf8.ValidString(v) || isASCII(v) {
				out = append(out, Str{
					Value:    v,
					Offset:   fileOff + uint64(start),
					Address:  addrAt(vaddr, fileOff, fileOff+uint64(start)),
					Section:  section,
					Length:   n,
					Encoding: encodingOf(v),
				})
			}
		}
	}
	for i, b := range data {
		printable := b >= 0x20 && b < 0x7f || b == '\t' || b == '\n' || b == '\r'
		if printable {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			flush(i)
			start = -1
		}
	}
	if start >= 0 {
		flush(len(data))
	}
	return out
}

func extractUTF16LE(data []byte, fileOff, vaddr uint64, section string, minLen int) []Str {
	var out []Str
	i := 0
	for i+1 < len(data) {
		j := i
		var run []rune
		for j+1 < len(data) {
			r := rune(data[j]) | rune(data[j+1])<<8
			if r < 0x20 || r > 0x7e {
				break
			}
			run = append(run, r)
			j += 2
		}
		if len(run) >= minLen {
			v := string(run)
			out = append(out, Str{
				Value:    v,
				Offset:   fileOff + uint64(i),
				Address:  addrAt(vaddr, fileOff, fileOff+uint64(i)),
				Section:  section,
				Length:   len(run) * 2,
				Encoding: "utf16le",
			})
			i = j + 2
			continue
		}
		i += 2
	}
	return out
}

func addrAt(sectionVaddr, sectionFileOff, filePos uint64) uint64 {
	if sectionVaddr == 0 {
		return 0
	}
	return sectionVaddr + (filePos - sectionFileOff)
}

func sanitizeRun(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7e {
			return false
		}
	}
	return true
}

func encodingOf(v string) string {
	for i := 0; i < len(v); i++ {
		if v[i] >= 0x80 {
			return "utf8"
		}
	}
	return "ascii"
}

// Classify returns the security-relevant classification for one string.
// The first pattern that confidently applies wins; when none do, nil is
// returned ("no security-relevant observation").
func Classify(s Str) *Classified {
	c := &Classified{Str: s}
	if reKey.MatchString(s.Value) {
		// Format matches known key/token shapes; needs manual confirmation.
		c.Class, c.Confidence = ClassPotentialKey, ConfMedium
		return c
	}
	if reIPv4.MatchString(s.Value) {
		return &Classified{Str: s, Class: "network_addr", Confidence: ConfMedium}
	}
	if reURL.MatchString(s.Value) {
		if u, err := url.Parse(s.Value); err == nil && u.Host != "" {
			c.Class, c.Confidence = ClassURL, ConfHigh
			return c
		}
	}
	if isLiteralIP(s.Value) {
		c.Class, c.Confidence = ClassIP, ConfHigh
		return c
	}
	if reCmd.MatchString(s.Value) {
		c.Class, c.Confidence = ClassCommand, ConfMedium
		return c
	}
	if reSQL.MatchString(s.Value) {
		c.Class, c.Confidence = ClassSQL, ConfMedium
		return c
	}
	if len(s.Value) <= 64 && reEnv.MatchString(s.Value) {
		c.Class, c.Confidence = ClassEnvVar, ConfMedium
		return c
	}
	if rePath.MatchString(s.Value) {
		c.Class, c.Confidence = ClassFilePath, ConfMedium
		return c
	}
	if reAuth.MatchString(strings.ToLower(trimNonWord(s.Value))) {
		// Keyword ≠ credential; keep confidence low on purpose.
		c.Class, c.Confidence = ClassAuthKeyword, ConfLow
		return c
	}
	if reCrypto.MatchString(strings.ToLower(s.Value)) {
		c.Class, c.Confidence = ClassCrypto, ConfLow
		return c
	}
	return nil
}

// ClassifyAll maps Classify over strings, dropping unclassified entries.
func ClassifyAll(strs []Str) []Classified {
	var out []Classified
	for _, s := range strs {
		if c := Classify(s); c != nil {
			out = append(out, *c)
		}
	}
	return out
}

func trimNonWord(s string) string {
	return strings.Trim(s, "\"'` \t\r\n()[]{};,")
}

// isLiteralIP checks whether the string's first token parses as an IP.
func isLiteralIP(v string) bool {
	tok := v
	if i := strings.IndexAny(tok, " \t\r\n"); i > 0 {
		tok = tok[:i]
	}
	return net.ParseIP(tok) != nil && strings.Contains(tok, ".") // IPv4-shaped only; bare "::" noise excluded
}
