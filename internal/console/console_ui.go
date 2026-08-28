package console

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/QYVORA/qyvora-aksum/internal/banner"
)

// ANSI style codes.
// Brand Gold #F5A623 (RGB 245, 166, 35) — primary logo accent
// Brand Bronze #D48806 (RGB 212, 136, 6) — secondary metallic accent
// Brand Charcoal #151619 (RGB 21, 22, 25) — background depth
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiAmber  = "\x1b[33m"
	ansiWhite  = "\x1b[37m"
	ansiGold   = "\x1b[38;2;245;166;35m"
	ansiBronze = "\x1b[38;2;212;136;6m"
)

const consoleSectionWidth = 60

// UI renders styled output for the Aksum console.
type UI struct {
	w     io.Writer
	color bool
	width int
}

func newUI(w io.Writer) *UI {
	u := &UI{w: w, width: consoleSectionWidth}
	if os.Getenv("NO_COLOR") == "" {
		u.color = writerIsTerminal(w)
	}
	return u
}

func (u *UI) Enabled() bool { return u.color }

func (u *UI) paint(s, code string) string {
	if !u.color || s == "" {
		return s
	}
	return code + s + ansiReset
}

func (u *UI) Gold(s string) string       { return u.paint(s, ansiGold) }
func (u *UI) BoldGold(s string) string   { return u.paint(s, ansiBold+ansiGold) }
func (u *UI) Bronze(s string) string     { return u.paint(s, ansiBronze) }
func (u *UI) BoldBronze(s string) string { return u.paint(s, ansiBold+ansiBronze) }
func (u *UI) Red(s string) string        { return u.paint(s, ansiRed) }
func (u *UI) Amber(s string) string      { return u.paint(s, ansiAmber) }
func (u *UI) White(s string) string      { return u.paint(s, ansiWhite) }
func (u *UI) BoldWhite(s string) string  { return u.paint(s, ansiBold+ansiWhite) }
func (u *UI) DimWhite(s string) string   { return u.paint(s, ansiDim+ansiWhite) }

func (u *UI) Section(title string) {
	label := strings.TrimSpace(title)
	if label == "" {
		u.Rule()
		return
	}
	inner := consoleSectionWidth - runeWidth(label) - 2
	if inner < 2 {
		inner = 2
	}
	left := inner / 2
	right := inner - left
	_, _ = fmt.Fprintf(u.w, "\n%s\n", u.DimWhite(strings.Repeat("─", left)+" "+label+" "+strings.Repeat("─", right)))
}

func (u *UI) Rule() {
	_, _ = fmt.Fprintln(u.w, u.DimWhite(strings.Repeat("─", consoleSectionWidth)))
}

func (u *UI) KV(key, value string) {
	_, _ = fmt.Fprintf(u.w, "  %s %s\n", u.BoldWhite(key+":"), u.White(value))
}

func (u *UI) Glyph(glyph string) string {
	switch glyph {
	case "+":
		return u.paint("[+]", ansiBold+ansiGold)
	case "*":
		return u.paint("[*]", ansiBold+ansiBronze)
	case "!":
		return u.paint("[!]", ansiBold+ansiAmber)
	case "x", "X":
		return u.paint("[x]", ansiBold+ansiRed)
	case ">":
		return u.paint("[>]", ansiBold+ansiWhite)
	case "v":
		return u.paint("[v]", ansiDim+ansiWhite)
	case "-":
		return u.paint("[-]", ansiDim+ansiWhite)
	default:
		return u.paint("["+glyph+"]", ansiBold+ansiWhite)
	}
}

func (u *UI) Status(glyph, format string, args ...any) {
	_, _ = fmt.Fprintf(u.w, "  %s %s\n", u.Glyph(glyph), u.White(fmt.Sprintf(format, args...)))
}

func (u *UI) Err(format string, args ...any) {
	_, _ = fmt.Fprintf(u.w, "  %s %s\n", u.Glyph("x"), u.paint(fmt.Sprintf(format, args...), ansiBold+ansiRed))
}

func (u *UI) Prompt(name, target string) string {
	base := u.paint(name, ansiBold+ansiGold)
	if target != "" {
		base += " " + u.paint("["+target+"]", ansiBold+ansiBronze)
	}
	return base + u.paint(" > ", ansiBold+ansiWhite)
}

func (u *UI) bannerGlyph(r rune) string {
	if !u.color || r == ' ' {
		return string(r)
	}
	switch r {
	case '@', '%', '#':
		return ansiGold + string(r) + ansiReset
	case '*', '+':
		return ansiBronze + string(r) + ansiReset
	case '=', '-', ':', '.':
		return ansiDim + ansiWhite + string(r) + ansiReset
	default:
		return string(r)
	}
}

func (u *UI) Banner(tagline string) {
	fmt.Fprintln(u.w)
	lines := strings.Split(banner.Art, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" && (line == lines[0] || line == lines[len(lines)-1]) {
			continue
		}
		var b strings.Builder
		for _, r := range line {
			b.WriteString(u.bannerGlyph(r))
		}
		fmt.Fprintln(u.w, b.String())
	}
	fmt.Fprintln(u.w)
	if tagline != "" {
		fmt.Fprintln(u.w, u.White("  "+tagline))
	}
	fmt.Fprintln(u.w, u.Gold("  QYVORA — https://qyvora.com"))
	fmt.Fprintln(u.w)
}

func (u *UI) BannerFoot(ver string) {
	u.Status(">", "v %s", ver)
	fmt.Fprintln(u.w, u.DimWhite("  type 'help' for commands, 'exit' to leave."))
	fmt.Fprintln(u.w)
}

func (u *UI) HUD(target, arch, cwd, ver string) {
	if !u.color {
		return
	}
	if target == "" {
		target = "none"
	}
	if arch == "" {
		arch = "none"
	}
	if cwd == "" {
		cwd = "?"
	}
	kv := func(k, v string) string {
		return u.DimWhite(k+" ") + u.White(v)
	}
	left := kv("target", target) + u.DimWhite("  ·  ") + kv("arch", arch) + u.DimWhite("  ·  ") + kv("cwd", cwd)
	right := u.Gold("v " + ver)

	cols := u.width
	if cols < 20 {
		cols = 80
	}
	pad := cols - runeWidth(left) - runeWidth(right) - 1
	if pad < 1 {
		pad = 1
	}
	fmt.Fprintf(u.w, "%s %s%s\n", u.paint("▮", ansiBold+ansiGold), left, strings.Repeat(" ", pad)+right)
}

func (u *UI) Table(headers []string, rows [][]string) {
	if len(headers) == 0 {
		return
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = runeWidth(h)
	}
	for _, r := range rows {
		for i := 0; i < len(headers) && i < len(r); i++ {
			if l := runeWidth(r[i]); l > widths[i] {
				widths[i] = l
			}
		}
	}

	var b strings.Builder
	for i, h := range headers {
		if i > 0 {
			b.WriteString("  ")
		}
		b.WriteString(padTo(u.BoldWhite(h), widths[i]))
	}
	fmt.Fprintln(u.w, b.String())

	for _, r := range rows {
		var rb strings.Builder
		for i := 0; i < len(headers); i++ {
			if i > 0 {
				rb.WriteString("  ")
			}
			var cell string
			if i < len(r) {
				cell = r[i]
			}
			rb.WriteString(padTo(u.White(cell), widths[i]))
		}
		fmt.Fprintln(u.w, rb.String())
	}
}

func runeWidth(s string) int {
	if strings.Contains(s, "\x1b") {
		s = stripANSI(s)
	}
	n := 0
	for _, r := range s {
		if isWideRune(r) {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func isWideRune(r rune) bool {
	switch {
	case r >= 0x1100 && r <= 0x115F,
		r >= 0x2329 && r <= 0x232A,
		r >= 0x2E80 && r <= 0xA4CF,
		r >= 0xAC00 && r <= 0xD7A3,
		r >= 0xF900 && r <= 0xFAFF,
		r >= 0xFE10 && r <= 0xFE19,
		r >= 0xFE30 && r <= 0xFE6F,
		r >= 0xFF00 && r <= 0xFF60,
		r >= 0xFFE0 && r <= 0xFFE6,
		r >= 0x1F300 && r <= 0x1F64F,
		r >= 0x1F900 && r <= 0x1F9FF:
		return true
	}
	return false
}

func stripANSI(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\x1b' {
			j := i + 1
			for j < len(s) && s[j] != 'm' {
				j++
			}
			if j < len(s) {
				j++
			}
			i = j
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

func padTo(s string, n int) string {
	pad := n - runeWidth(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}

func writerIsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
