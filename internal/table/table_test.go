package table

import (
	"strings"
	"testing"
)

func TestBasicRender(t *testing.T) {
	tt := New("name", "type", "size").SetWidth(80)
	tt.AddRow(".text", "PROGBITS", "24576")
	tt.AddRow(".rodata", "PROGBITS", "8192")

	out := tt.String()
	for _, want := range []string{"NAME", "TYPE", "SIZE", ".text", "24576", ".rodata", "8192"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	// No box-drawing borders or horizontal rules.
	for _, forbid := range []string{"┌", "│", "└", "├", "┼", "─", "|", "+"} {
		if strings.Contains(out, forbid) {
			t.Fatalf("output must not contain %q:\n%s", forbid, out)
		}
	}

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("table produced %d lines, want 3 (header + 2 rows):\n%s", len(lines), out)
	}
}

func TestEmptyTableRendersHeaderOnly(t *testing.T) {
	tt := New("h1", "h2")
	if !tt.Empty() || tt.Len() != 0 {
		t.Fatal("fresh table must be empty")
	}
	out := tt.String()
	if strings.Count(strings.TrimRight(out, "\n"), "\n") != 0 {
		t.Fatalf("empty table should render only the header row:\n%q", out)
	}
	if !strings.Contains(out, "H1") || !strings.Contains(out, "H2") {
		t.Fatalf("header labels missing: %q", out)
	}
}

func TestLongValuesTruncatedToWidth(t *testing.T) {
	long := strings.Repeat("A", 300)
	tt := New("value").SetWidth(50)
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
	tt := New("num").SetAlign(0, AlignRight).SetWidth(80)
	tt.AddRow("12")
	tt.AddRow("1234567")
	lines := strings.Split(strings.TrimRight(tt.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("table produced %d lines, want 3:\n%s", len(lines), tt.String())
	}
	// All data rows must be the same width and right-aligned: "12" is padded
	// on the left so both columns line up at the same right edge.
	if len([]rune(lines[1])) != len([]rune(lines[2])) {
		t.Fatalf("row widths differ (%d vs %d):\n%s", len([]rune(lines[1])), len([]rune(lines[2])), tt.String())
	}
	if strings.HasSuffix(lines[1], "12") && !strings.HasPrefix(lines[1], " ") {
		t.Fatalf("'12' must be right-aligned with leading padding:\n%s", tt.String())
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

func TestHeadersUppercased(t *testing.T) {
	tt := New("address", "Name")
	if !strings.Contains(tt.String(), "ADDRESS") || !strings.Contains(tt.String(), "NAME") {
		t.Fatal("headers must render uppercase")
	}
}
