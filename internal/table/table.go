// Package table renders aksum's structured results as terminal tables.
//
// One renderer serves every command so reverse-engineering datasets
// (sections, symbols, functions, findings, ...) share a single visual
// language instead of per-command ASCII art. The renderer handles column
// widths, alignment, terminal-width truncation of long values, and empty
// result sets. Tables use clean aligned columns with no box-drawing borders
// or horizontal rules, matching the ecosystem's console style.
//
// Tables are presentation-only: machine-readable output (--format json)
// never passes through this package.
package table

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Align selects horizontal cell alignment within a column.
type Align int

const (
	// AlignLeft pads cells on the right (default).
	AlignLeft Align = iota
	// AlignRight pads cells on the left (numeric columns).
	AlignRight
)

// DefaultWidth is used when the terminal size cannot be determined.
const DefaultWidth = 100

// MinTableWidth floors the table width so narrow terminals still render
// readable columns instead of collapsing every cell to one character.
const MinTableWidth = 40

// Table accumulates rows and renders them with computed column widths.
type Table struct {
	headers []string
	rows    [][]string
	align   []Align
	width   int // max total rendered width incl. gaps; 0 = auto-detect
}

// New starts a table with the given header labels.
func New(headers ...string) *Table {
	t := &Table{headers: append([]string{}, headers...)}
	for range headers {
		t.align = append(t.align, AlignLeft)
	}
	t.width = DetectWidth()
	return t
}

// SetAlign sets alignment for one column (0-based).
func (t *Table) SetAlign(col int, a Align) *Table {
	if col >= 0 && col < len(t.align) {
		t.align[col] = a
	}
	return t
}

// SetWidth overrides the detected terminal-width cap.
func (t *Table) SetWidth(w int) *Table { t.width = w; return t }

// AddRow appends one data row. Missing cells are padded; extra cells beyond
// the header count are ignored so malformed producers cannot skew layout.
func (t *Table) AddRow(cells ...string) {
	row := make([]string, len(t.headers))
	for i := range row {
		if i < len(cells) {
			row[i] = sanitize(cells[i])
		}
	}
	t.rows = append(t.rows, row)
}

// Empty reports whether no data rows were added.
func (t *Table) Empty() bool { return len(t.rows) == 0 }

// Len returns the number of data rows.
func (t *Table) Len() int { return len(t.rows) }

// Render writes the table to w. An empty table renders only its header row;
// callers decide how to message empty result sets. Write errors are the
// caller's concern (a failing terminal pipe cannot be recovered here), so
// they are explicitly discarded.
func (t *Table) Render(w io.Writer) {
	_, _ = fmt.Fprint(w, t.String())
}

// String renders the table to a string: an uppercase header row followed by
// aligned data rows. Columns are separated by two spaces; no borders or
// horizontal rules are drawn.
func (t *Table) String() string {
	widths := t.computeWidths()
	var b strings.Builder

	run := func(cells []string) {
		for i := range widths {
			if i > 0 {
				b.WriteString("  ")
			}
			cell := ""
			if i < len(cells) {
				cell = cells[i]
			}
			cell = t.fitPad(cell, widths[i], t.align[i])
			if i == len(widths)-1 {
				cell = strings.TrimRight(cell, " ")
			}
			b.WriteString(cell)
		}
		b.WriteString("\n")
	}

	run(upperAll(t.headers))
	for _, r := range t.rows {
		run(r)
	}
	return b.String()
}

// computeWidths sizes each column to its widest visible cell, then shrinks
// over-wide columns widest-first when the total exceeds the width budget.
func (t *Table) computeWidths() []int {
	n := len(t.headers)
	widths := make([]int, n)
	for i, h := range upperAll(t.headers) {
		widths[i] = displayWidth(h)
	}
	for _, r := range t.rows {
		for i, c := range r {
			if i < n && displayWidth(c) > widths[i] {
				widths[i] = displayWidth(c)
			}
		}
	}

	// Two-space gaps between columns consume the width budget.
	gaps := 2 * (n - 1)
	maxTotal := t.width - gaps
	if maxTotal < MinTableWidth-gaps {
		maxTotal = MinTableWidth - gaps
	}
	for sum(widths) > maxTotal {
		idx := argmax(widths)
		if widths[idx] <= 3 {
			break
		}
		widths[idx]--
	}
	return widths
}

// fitPad truncates a cell to its column and pads it per alignment.
func (t *Table) fitPad(s string, w int, a Align) string {
	if dw := displayWidth(s); dw > w {
		const ell = "…"
		if w <= utf8.RuneCountInString(ell) {
			return ell[:min(w, len(ell))]
		}
		runes := []rune(s)
		s = string(runes[:w-utf8.RuneCountInString(ell)]) + ell
	}
	gap := w - displayWidth(s)
	if gap <= 0 {
		return s
	}
	pad := strings.Repeat(" ", gap)
	if a == AlignRight {
		return pad + s
	}
	return s + pad
}

func sum(ws []int) int {
	s := 0
	for _, w := range ws {
		s += w
	}
	return s
}

func argmax(ws []int) int {
	idx := 0
	for i, w := range ws {
		if w > ws[idx] {
			idx = i
		}
	}
	return idx
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func upperAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToUpper(s)
	}
	return out
}

// displayWidth counts runes — aksum sanitizes control characters before
// cells are added, so rune count approximates terminal columns closely
// enough for our data (ASCII symbol names, addresses, paths).
func displayWidth(s string) int { return utf8.RuneCountInString(s) }

var ctrlReplacer = buildCtrlReplacer()

func buildCtrlReplacer() *strings.Replacer {
	var pairs []string
	for r := rune(1); r < ' '; r++ {
		pairs = append(pairs, string(r), ".")
	}
	pairs = append(pairs, "\n", ".", "\r", ".", "\t", ".", "\x7f", ".")
	return strings.NewReplacer(pairs...)
}

// sanitize strips control characters and ANSI escapes from binary-derived
// cell text before it reaches the terminal.
func sanitize(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r < ' ' || r == 0x7f }) {
		return s
	}
	return ctrlReplacer.Replace(s)
}

// DetectWidth reports the current terminal width: COLUMNS overrides,
// then TIOCGWINSZ probing, then DefaultWidth.
func DetectWidth() int {
	if w := os.Getenv("COLUMNS"); w != "" {
		if n, err := strconv.Atoi(w); err == nil && n >= MinTableWidth {
			return n
		}
	}
	return probeTermWidth()
}
