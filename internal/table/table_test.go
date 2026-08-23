package table

import (
	"strings"
	"testing"
)

func TestBasicUnicodeRender(t *testing.T) {
	tt := New("name", "type", "size").
		SetStyle(UnicodeStyle).
		SetWidth(80)
	tt.AddRow(".text", "PROGBITS", "24576")
	tt.AddRow(".rodata", "PROGBITS", "8192")

	out := tt.String()
	for _, want := range []string{"┌", "│ NAME", ".text", "24576", "└"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "├") || !strings.Contains(out, "┼") {
		t.Fatalf("missing row separator:\n%s", out)
	}

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	width := len([]rune(lines[0]))
	for i, l := range lines {
		if len([]rune(l)) != width {
			t.Fatalf("line %d width %d != %d (ragged box):\n%s", i, len([]rune(l)), width, out)
		}
	}
}

func TestASCIIFallback(t *testing.T) {
	tt := New("a").SetStyle(ASCIIStyle).SetWidth(40)
	tt.AddRow("x")
	out := tt.String()
	if !strings.Contains(out, "+") || strings.ContainsAny(out, "┌│└") {
		t.Fatalf("ASCII style not used: %q", out)
	}
}

func TestEmptyTableRendersHeaderOnly(t *testing.T) {
	tt := New("h1", "h2").SetStyle(UnicodeStyle)
	if !tt.Empty() || tt.Len() != 0 {
		t.Fatal("fresh table must be empty")
	}
	out := tt.String()
	if strings.Count(out, "\n") != 3 {
		t.Fatalf("empty table should render 3 lines (top/header/bottom):\n%q", out)
	}
	if strings.Contains(out, "│\n") && strings.Count(out, "│") != 4 {
		t.Logf("note: header row uses verticals: %q", out)
	}
}

func TestLongValuesTruncatedToWidth(t *testing.T) {
	long := strings.Repeat("A", 300)
	tt := New("value").SetWidth(50).SetStyle(UnicodeStyle)
	tt.AddRow(long)
	out := tt.String()
	for _, l := range strings.Split(out, "\n") {
		if l != "" && len([]rune(l)) > 50 {
			t.Fatalf("line exceeds width 50 (%d runes): %q", len([]rune(l)), l)
		}
	}
	if !strings.Contains(out, "…") {
		t.Fatalf("truncation should append ellipsis:\n%s", out)
	}
}

func TestControlCharactersSanitized(t *testing.T) {
	tt := New("v")
	tt.AddRow("bad\x1b[31mansi\x07tail")
	cell := tt.rows[0][0]
	if strings.ContainsAny(cell, "\x1b\x07") {
		t.Fatalf("control chars survived sanitization: %q", cell)
	}
	if strings.Contains(cell, "[31m") == false {
		t.Fatalf("escape payload should remain as literal text: %q", cell)
	}
}

func TestAlignmentRight(t *testing.T) {
	tt := New("num").SetAlign(0, AlignRight).SetStyle(UnicodeStyle)
	tt.AddRow("12")
	tt.AddRow("1234567")
	out := tt.String()
	if !strings.Contains(out, "      12 │") {
		t.Fatalf("right alignment missing:\n%s", out)
	}
}

func TestExtraCellsIgnoredMissingPadded(t *testing.T) {
	tt := New("a", "b")
	tt.AddRow("only-a", "x", "surplus")
	row := tt.rows[0]
	if len(row) != 2 {
		t.Fatalf("row length = %d, want 2", len(row))
	}
	out := tt.String()
	if !strings.Contains(out, "only-a") {
		t.Fatalf("missing data: %s", out)
	}
}

func TestDetectWidthEnvOverride(t *testing.T) {
	t.Setenv("COLUMNS", "120")
	if got := DetectWidth(); got < 120 {
		t.Fatalf("DetectWidth() = %d, want >= 120 from COLUMNS", got)
	}
	t.Setenv("COLUMNS", "5") // below floor: ignored
	if got := DetectWidth(); got < MinTableWidth {
		t.Fatalf("DetectWidth() = %d, want >= floor", got)
	}
}

func TestPickStyleRestrictedTerminal(t *testing.T) {
	t.Setenv("TERM", "dumb")
	t.Setenv("LC_ALL", "C.UTF-8")
	if PickStyle() != ASCIIStyle {
		t.Fatal("TERM=dumb must select ASCII style")
	}
	t.Setenv("TERM", "xterm-256color")
	if PickStyle() != UnicodeStyle {
		t.Fatal("UTF-8 terminal must select Unicode style")
	}
	t.Setenv("LANG", "C")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_CTYPE", "")
	if PickStyle() != ASCIIStyle {
		t.Fatal("non-UTF-8 locale must select ASCII style")
	}
}

func TestHeadersUppercased(t *testing.T) {
	tt := New("address", "Name")
	if !strings.Contains(tt.String(), "ADDRESS") || !strings.Contains(tt.String(), "NAME") {
		t.Fatal("headers must render uppercase")
	}
}
