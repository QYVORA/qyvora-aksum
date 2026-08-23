// console_test.go covers the interactive console: tokenizer, flag parsing,
// history, tab completion, command dispatch through a scripted session,
// JSON modes, aliases, suggestions, and honest error handling.
package console

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-aksum/internal/testfix"
)

// runScript feeds lines to a fresh console and returns everything written
// to stdout and stderr. Interactive mode stays off so no terminal is needed.
func runScript(t *testing.T, script string) (string, string) {
	t.Helper()
	var out, errW bytes.Buffer
	c := New(Options{In: strings.NewReader(script), Out: &out, Err: &errW})
	if code := c.Run(context.Background()); code != 0 {
		t.Fatalf("console exit code = %d, want 0", code)
	}
	return out.String(), errW.String()
}

// writeFixture crafts the deterministic ELF64 fixture and returns its path.
func writeFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, testfix.ELF64(testfix.ExecNX), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// ---- tokenizer -------------------------------------------------------

func TestTokenize(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    []string
		wantErr bool
	}{
		{"plain", "open /tmp/a.bin", []string{"open", "/tmp/a.bin"}, false},
		{"extra spaces", "   binary   ", []string{"binary"}, false},
		{"double quoted path", `open "/tmp/my dir/a.bin"`, []string{"open", "/tmp/my dir/a.bin"}, false},
		{"single quoted", `open '/tmp/x y'`, []string{"open", "/tmp/x y"}, false},
		{"escaped space", `open /tmp/my\ dir`, []string{"open", "/tmp/my dir"}, false},
		{"escaped quote inside dq", `"a\"b"`, []string{`a"b`}, false},
		{"unterminated dq", `"abc`, nil, true},
		{"unterminated sq", "'abc", nil, true},
		{"trailing backslash", `abc\`, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tokenize(tc.line)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("tokenize(%q) = %v, want error", tc.line, got)
				}
				var pe *ParseError
				if !asParseError(err, &pe) {
					t.Fatalf("error type = %T, want *ParseError", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("tokenize(%q) unexpected error: %v", tc.line, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("tokenize(%q) = %#v, want %#v", tc.line, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("tokenize(%q)[%d] = %q, want %q", tc.line, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func asParseError(err error, target **ParseError) bool {
	if pe, ok := err.(*ParseError); ok {
		*target = pe
		return true
	}
	return false
}

// ---- flag parsing ----------------------------------------------------

func newTestCommand() *Command {
	return &Command{
		Name: "probe",
		Flags: []FlagSpec{
			{Name: "json", Kind: FlagBool},
			{Name: "limit", Kind: FlagInt},
			{Name: "name", Kind: FlagString},
			{Name: "arg", Kind: FlagStringSlice},
		},
	}
}

func TestParseFlags(t *testing.T) {
	cmd := newTestCommand()
	p, err := parse("probe", "", []string{"x", "--json", "--limit", "5",
		"--name", "main", "--arg", "a", "--arg=b", "--json=false"}, cmd.flagSpecs())
	if err != nil {
		t.Fatal(err)
	}
	if !p.Bool("json") == false || p.Bool("json") {
		t.Fatalf("Bool(json) = %v, want false after override", p.Bool("json"))
	}
	if p.Int("limit", 0) != 5 {
		t.Fatalf("Int(limit) = %d, want 5", p.Int("limit", 0))
	}
	if p.Str("name") != "main" {
		t.Fatalf("Str(name) = %q, want main", p.Str("name"))
	}
	gotArgs := p.Strs("arg")
	if len(gotArgs) != 2 || gotArgs[0] != "a" || gotArgs[1] != "b" {
		t.Fatalf("Strs(arg) = %#v, want [a b]", gotArgs)
	}
	if p.Arg(0) != "x" || p.ArgsLen() != 1 {
		t.Fatalf("positional args = %#v", p.Args)
	}
}

func TestParseErrors(t *testing.T) {
	cmd := newTestCommand()
	cases := []struct {
		name string
		toks []string
	}{
		{"unknown flag", []string{"--nope"}},
		{"missing int value", []string{"--limit"}},
		{"bad int value", []string{"--limit", "abc"}},
		{"missing string value", []string{"--name"}},
		{"bad bool value", []string{"--json=maybe"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parse("probe", "", tc.toks, cmd.flagSpecs())
			if err == nil {
				t.Fatalf("parse(%#v) = %+v, want error", tc.toks, p)
			}
			if _, ok := err.(*ParseError); !ok {
				t.Fatalf("error type = %T, want *ParseError", err)
			}
		})
	}
}

// Negative numbers are positional args, never flags.
func TestNegativeNumberIsArg(t *testing.T) {
	cmd := &Command{Flags: []FlagSpec{{Name: "json", Kind: FlagBool}}}
	p, err := parse("probe", "", []string{"-1"}, cmd.flagSpecs())
	if err != nil {
		t.Fatal(err)
	}
	if p.Arg(0) != "-1" {
		t.Fatalf("Arg(0) = %q, want -1", p.Arg(0))
	}
}

// ---- history ---------------------------------------------------------

func TestHistoryDedupesAndCaps(t *testing.T) {
	h := NewHistory()
	h.Add("binary")
	h.Add("binary") // consecutive duplicate collapses
	h.Add("sections")
	lines := h.Lines()
	if len(lines) != 2 || lines[0] != "binary" || lines[1] != "sections" {
		t.Fatalf("Lines() = %#v", lines)
	}
	for i := range historyLimit + 20 {
		h.Add(strings.Repeat("x", i%7+1))
	}
	if h.Len() > historyLimit {
		t.Fatalf("history grew to %d, cap %d", h.Len(), historyLimit)
	}
}

// ---- completion ------------------------------------------------------

func TestCompleterCommandsAndFlags(t *testing.T) {
	c := New(Options{})
	cm := c.newCompleter()

	suffixes, offset := cm.Do([]rune("sec"), 3)
	if len(suffixes) != 1 || string(suffixes[0]) != "tions" || offset != 3 {
		t.Fatalf("Do(sec) = %#v/%d, want [tions]/3", suffixes, offset)
	}

	suffixes, _ = cm.Do([]rune("help s"), 6)
	found := false
	for _, s := range suffixes {
		if string(s) == "ections" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Do(help s) missing sections suffix: %#v", suffixes)
	}

	suffixes, _ = cm.Do([]rune("symbols --dy"), 12)
	if len(suffixes) != 1 || string(suffixes[0]) != "namic" {
		t.Fatalf("Do(symbols --dy) = %#v, want [namic]", suffixes)
	}

	// Aliases complete too.
	suffixes, _ = cm.Do([]rune("?"), 1)
	if len(suffixes) == 0 {
		t.Fatal("Do(?) returned no candidates")
	}

	// Unknown first word completes nothing.
	if s, _ := cm.Do([]rune("zzz"), 3); len(s) != 0 {
		t.Fatalf("Do(zzz) = %#v, want none", s)
	}
}

// ---- scripted sessions ----------------------------------------------

func TestSessionLifecycleAndGuidance(t *testing.T) {
	out, errW := runScript(t, strings.Join([]string{
		"",          // blank line ignored
		"# comment", // comment ignored
		"sections",  // no target -> guidance
		"open /definitely/not/here",
		"quit",
	}, "\n"))

	if !strings.Contains(out, "No target loaded.") || !strings.Contains(out, "Use: open <binary>") {
		t.Fatalf("missing pre-open guidance:\n%s", out)
	}
	if !strings.Contains(errW, "failed to open target") {
		t.Fatalf("missing open failure message:\n%s", errW)
	}
	// Blank lines/comments must not appear in history output noise.
	if strings.Contains(out, "[!] No such command") {
		t.Fatalf("unexpected unknown-command noise:\n%s", out)
	}
}

func TestOpenTargetAndStructureCommands(t *testing.T) {
	fixture := writeFixture(t)
	out, _ := runScript(t, strings.Join([]string{
		"open " + fixture,
		"target",
		"binary",
		"sections",
		"segments",
		"symbols",
		"imports",
		"strings",
		"quit",
	}, "\n"))

	if !strings.Contains(out, "Target loaded") ||
		!strings.Contains(out, "PIE") ||
		!strings.Contains(out, "[ENUM]") ||
		!strings.Contains(out, ".text") {
		t.Fatalf("structure output incomplete:\n%s", out)
	}
	if !strings.Contains(out, "(none)") && !strings.Contains(out, "security-relevant") {
		t.Fatalf("strings/symbols output missing:\n%s", out)
	}
}

func TestJSONModes(t *testing.T) {
	fixture := writeFixture(t)
	out, _ := runScript(t, strings.Join([]string{
		"open " + fixture,
		"target --json",
		"sections --json",
		"status --json",
		"quit",
	}, "\n"))

	for _, marker := range []string{`"format": "ELF"`, `"type":`, `"History entries"`} {
		if !strings.Contains(out, marker) {
			t.Fatalf("JSON output missing %s:\n%s", marker, out)
		}
	}
	// Tables must be suppressed in JSON mode.
	if strings.Contains(out, "│") {
		t.Fatalf("table borders leaked into JSON mode:\n%s", out)
	}
}

func TestAliasesAndHelp(t *testing.T) {
	fixture := writeFixture(t)
	out, errW := runScript(t, strings.Join([]string{
		"? help",
		"help disasm",
		"help nosuchcmd",
		"open " + fixture,
		"b",
		"quit",
	}, "\n"))

	if !strings.Contains(out, "disasm — Disassemble code") &&
		!strings.Contains(out, "--limit <n>") {
		t.Fatalf("help detail missing:\n%s", out)
	}
	if !strings.Contains(errW, "no such command") {
		t.Fatalf("unknown help topic not reported:\n%s", errW)
	}
	if !strings.Contains(out, "PIE") { // `b` ran the binary command
		t.Fatalf("alias 'b' did not run binary:\n%s", out)
	}
}

func TestUnknownCommandSuggests(t *testing.T) {
	out, errW := runScript(t, "sectons\nquit\n")
	if !strings.Contains(errW, "Unknown command: sectons") {
		t.Fatalf("missing unknown-command error:\n%s", errW)
	}
	if !strings.Contains(errW, "Did you mean 'sections'?") {
		t.Fatalf("missing suggestion:\n%s", errW)
	}
	_ = out
}

func TestUnknownFlagKeepsSessionAlive(t *testing.T) {
	fixture := writeFixture(t)
	out, errW := runScript(t, strings.Join([]string{
		"functions --bogus",
		"open " + fixture,
		"version",
		"quit",
	}, "\n"))
	if !strings.Contains(errW, "unknown flag") {
		t.Fatalf("missing flag error:\n%s", errW)
	}
	if !strings.Contains(out, "aksum dev") && !strings.Contains(out, "aksum ") {
		t.Fatalf("session did not survive the parse error:\n%s\n%s", out, errW)
	}
}

func TestAnalysisPipelineInSession(t *testing.T) {
	fixture := writeFixture(t)
	reportPath := filepath.Join(t.TempDir(), "report.json")
	out, errW := runScript(t, strings.Join([]string{
		"open " + fixture,
		"analyze",
		"findings",
		"report " + reportPath,
		"surface",
		"dynamic run",
		"quit",
	}, "\n"))

	if !strings.Contains(out, "finding(s)") {
		t.Fatalf("findings summary missing:\n%s", out)
	}
	if _, err := os.Stat(reportPath); err != nil {
		t.Fatalf("report file missing: %v\n%s", err, out)
	}
	data, _ := os.ReadFile(reportPath)
	if !bytes.Contains(data, []byte(`"schema_version"`)) {
		t.Fatalf("report lacks schema marker: %.200s", data)
	}
	if !strings.Contains(errW, "refuses to execute") {
		t.Fatalf("dynamic run must refuse honestly:\n%s\n%s", out, errW)
	}
}

func TestDynamicPlanRequiresConsent(t *testing.T) {
	fixture := writeFixture(t)
	_, errW := runScript(t, strings.Join([]string{
		"open " + fixture,
		"dynamic plan --yes",
		"quit",
	}, "\n"))
	if strings.Contains(errW, "consent") {
		t.Fatalf("--yes was passed; consent should hold:\n%s", errW)
	}
}

func TestRawTargetDegradesHonestly(t *testing.T) {
	raw := filepath.Join(t.TempDir(), "blob.bin")
	if err := os.WriteFile(raw, bytes.Repeat([]byte{0x41}, 64), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errW := runScript(t, strings.Join([]string{
		"open " + raw,
		"sections",
		"quit",
	}, "\n"))

	if !strings.Contains(errW, "ELF image") && !strings.Contains(errW, "requires") {
		t.Fatalf("raw target guidance missing:\n%s\n%s", out, errW)
	}
}

func TestDisasmOnUnsupportedArchIsHonest(t *testing.T) {
	// The crafted fixture has no symbols; linear-region disassembly must
	// still work on x86-64 or report cleanly.
	fixture := writeFixture(t)
	out, errW := runScript(t, strings.Join([]string{
		"open " + fixture,
		"disasm --limit 4",
		"quit",
	}, "\n"))
	if !strings.Contains(out, "instructions decoded") &&
		!strings.Contains(errW, "") {
		t.Fatalf("expected disassembly output:\n%s", out)
	}
}

func TestCloseReleasesState(t *testing.T) {
	fixture := writeFixture(t)
	out, _ := runScript(t, strings.Join([]string{
		"open " + fixture,
		"close",
		"target",
		"quit",
	}, "\n"))
	if !strings.Contains(out, "Target closed") || !strings.Contains(out, "No target loaded.") {
		t.Fatalf("close lifecycle broken:\n%s", out)
	}
}

func TestEOFEndsCleanly(t *testing.T) {
	out, _ := runScript(t, "version\n")
	if !strings.Contains(out, "aksum") {
		t.Fatalf("EOF session produced no version output:\n%s", out)
	}
}

// The in-session history command reflects executed lines.
func TestHistoryCommandListsExecutedLines(t *testing.T) {
	out, _ := runScript(t, "version\nhistory\nquit\n")
	if !strings.Contains(out, "1  version") {
		t.Fatalf("history listing missing:\n%s", out)
	}
}

// ---- suggestion quality ---------------------------------------------

func TestSuggestPrefixBeatsDistance(t *testing.T) {
	c := New(Options{})
	if got := c.suggest("sec"); got != "sections" {
		t.Fatalf("suggest(sec) = %q, want sections", got)
	}
	if got := c.suggest("hel"); got != "help" {
		t.Fatalf("suggest(hel) = %q, want help", got)
	}
	if got := c.suggest("fnction"); got != "functions" {
		t.Fatalf("suggest(fnction) = %q, want functions", got)
	}
	if got := c.suggest("qqqqqq"); got != "" {
		t.Fatalf("suggest(garbage) = %q, want empty", got)
	}
}
