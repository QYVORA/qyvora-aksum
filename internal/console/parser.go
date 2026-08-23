// parser.go implements aksum console command-line parsing: whitespace
// splitting, quoted paths, flag parsing with typed values, and validation.
// Parsing is pure — no I/O — so it is trivially testable.
package console

import (
	"fmt"
	"strconv"
	"strings"
)

// FlagKind describes a command flag's value type.
type FlagKind int

const (
	// FlagBool is a switch; "--x" sets it true, "--x=false" overrides.
	FlagBool FlagKind = iota
	// FlagString takes one string value ("--out path", "--out=path").
	FlagString
	// FlagInt takes one integer value.
	FlagInt
	// FlagStringSlice accumulates repeatable values ("--arg a --arg b").
	FlagStringSlice
)

// FlagSpec declares one flag accepted by a command.
type FlagSpec struct {
	Name string
	Kind FlagKind
}

func (f FlagSpec) usage() string {
	switch f.Kind {
	case FlagBool:
		return "--" + f.Name
	case FlagInt:
		return "--" + f.Name + " <n>"
	case FlagStringSlice:
		return "--" + f.Name + " <value> (repeatable)"
	default:
		return "--" + f.Name + " <value>"
	}
}

// ParseError is a concise, user-facing parsing failure. The console prints
// its message and returns to the prompt — never a stack trace.
type ParseError struct{ msg string }

func (e *ParseError) Error() string { return e.msg }

func parseErrf(format string, a ...any) error {
	return &ParseError{msg: fmt.Sprintf(format, a...)}
}

// Parsed is one validated console command invocation.
type Parsed struct {
	Name  string            // canonical command name
	Raw   string            // original line
	Args  []string          // positional arguments
	Flags map[string]flagValue
	spec  map[string]FlagSpec
}

type flagValue struct {
	str   string
	num   int
	boolV bool
	slice []string
}

// Bool returns the value of a boolean flag (false when absent).
func (p *Parsed) Bool(name string) bool {
	if v, ok := p.Flags[name]; ok {
		return v.boolV
	}
	return false
}

// Str returns the value of a string flag ("" when absent).
func (p *Parsed) Str(name string) string {
	if v, ok := p.Flags[name]; ok {
		return v.str
	}
	return ""
}

// Strs returns accumulated values of a repeatable flag.
func (p *Parsed) Strs(name string) []string {
	if v, ok := p.Flags[name]; ok {
		return v.slice
	}
	return nil
}

// Int returns the value of an integer flag (def when absent).
func (p *Parsed) Int(name string, def int) int {
	if v, ok := p.Flags[name]; ok {
		return v.num
	}
	return def
}

// Arg returns the i-th positional argument or "" when absent.
func (p *Parsed) Arg(i int) string {
	if i < len(p.Args) {
		return p.Args[i]
	}
	return ""
}

// ArgsLen returns the positional argument count.
func (p *Parsed) ArgsLen() int { return len(p.Args) }

// tokenize splits a raw line into tokens honoring single quotes, double
// quotes, and backslash escapes outside quotes. Unterminated quotes are a
// parse error, not a silent truncation.
func tokenize(line string) ([]string, error) {
	var toks []string
	var cur strings.Builder
	inToken := false
	for i := 0; i < len(line); {
		r := line[i]
		switch r {
		case ' ', '\t':
			if inToken {
				toks = append(toks, cur.String())
				cur.Reset()
				inToken = false
			}
			i++
		case '\'':
			inToken = true
			end := strings.IndexByte(line[i+1:], '\'')
			if end < 0 {
				return nil, parseErrf("unterminated single quote")
			}
			cur.WriteString(line[i+1 : i+1+end])
			i += end + 2
		case '"':
			inToken = true
			rest := line[i+1:]
			var j int
			for j = 0; j < len(rest); j++ {
				if rest[j] == '"' {
					break
				}
				if rest[j] == '\\' && j+1 < len(rest) &&
					(rest[j+1] == '"' || rest[j+1] == '\\') {
					j++ // keep escaped char verbatim below
					continue
				}
			}
			if j >= len(rest) {
				return nil, parseErrf("unterminated double quote")
			}
			cur.WriteString(strings.ReplaceAll(
				strings.ReplaceAll(rest[:j], `\"`, `"`), `\\`, `\`))
			i += j + 2
		case '\\':
			if i+1 >= len(line) {
				return nil, parseErrf("trailing backslash")
			}
			inToken = true
			cur.WriteByte(line[i+1])
			i += 2
		default:
			inToken = true
			cur.WriteByte(r)
			i++
		}
	}
	if inToken {
		toks = append(toks, cur.String())
	}
	return toks, nil
}

// parse validates tokens against the resolved command's flag specs and
// produces the typed Parsed form. cmd may be nil for unknown words — the
// caller decides how to report those after consulting the registry.
func parse(name, raw string, toks []string, spec map[string]FlagSpec) (*Parsed, error) {
	p := &Parsed{Name: name, Raw: raw, Flags: map[string]flagValue{}, spec: spec}
	for i := 0; i < len(toks); i++ {
		tok := toks[i]
		if !isFlagToken(tok) {
			p.Args = append(p.Args, tok)
			continue
		}
		flagName := strings.TrimLeft(tok, "-")
		var inline string
		hasInline := false
		if eq := strings.IndexByte(flagName, '='); eq >= 0 {
			inline, hasInline = flagName[eq+1:], true
			flagName = flagName[:eq]
		}
		fs, ok := spec[flagName]
		if !ok || fs.Name == "" {
			return nil, parseErrf("unknown flag %s", tok)
		}
		switch fs.Kind {
		case FlagBool:
			v := "true"
			if hasInline {
				v = inline
			}
			b, err := strconv.ParseBool(v)
			if err != nil {
				return nil, parseErrf("invalid value for --%s: %q (true, false)", flagName, v)
			}
			p.Flags[flagName] = flagValue{boolV: b}
		case FlagInt:
			v := inline
			if !hasInline {
				if i+1 >= len(toks) {
					return nil, parseErrf("--%s requires a numeric value", flagName)
				}
				i++
				v = toks[i]
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, parseErrf("--%s expects an integer, got %q", flagName, v)
			}
			p.Flags[flagName] = flagValue{num: n}
		default: // FlagString
			v := inline
			if !hasInline {
				if i+1 >= len(toks) {
					return nil, parseErrf("--%s requires a value", flagName)
				}
				i++
				v = toks[i]
			}
			if fs.Kind == FlagStringSlice {
				fv := p.Flags[flagName]
				fv.slice = append(fv.slice, v)
				p.Flags[flagName] = fv
			} else {
				p.Flags[flagName] = flagValue{str: v}
			}
		}
	}
	return p, nil
}

// isFlagToken reports whether tok looks like a flag ("-x", "--x") rather
// than a negative number or bare dash.
func isFlagToken(tok string) bool {
	if len(tok) < 2 || tok[0] != '-' {
		return false
	}
	second := tok[1]
	if second == '-' {
		return true
	}
	return second < '0' || second > '9'
}
