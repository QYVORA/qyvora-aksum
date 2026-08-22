package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	strscan "github.com/QYVORA/qyvora-aksum/internal/analysis/strings"
	"github.com/QYVORA/qyvora-aksum/internal/analysis/structure"
	"github.com/QYVORA/qyvora-aksum/internal/output"
	"github.com/QYVORA/qyvora-aksum/internal/security/class"
)

// newPrinter builds the shared human-output renderer from global flags.
func newPrinter() *output.Printer {
	p := output.New()
	if formatFlag != "" {
		p.SetFormat(formatFlag)
	}
	p.SetQuiet(quietFlag)
	return p
}

// emit renders v: a table in terminal mode, JSON in json mode.
func emit(_ any, v any) error {
	if newPrinter().Format() == "json" {
		return json.NewEncoder(os.Stdout).Encode(v)
	}
	switch rows := v.(type) {
	case []structure.Section:
		printSectionTable(rows)
	case []structure.Segment:
		printSegmentTable(rows)
	case []structure.Symbol:
		printSymbolTable(rows)
	default:
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	}
	return nil
}

func printSectionTable(sections []structure.Section) {
	fmt.Printf("%-24s %-10s %-14s %-10s %8s  %s\n", "NAME", "TYPE", "ADDRESS", "OFFSET", "SIZE", "FLAGS")
	for _, s := range sections {
		if s.Name == "" && s.Type == "NULL" {
			continue // header-null row is noise in human output
		}
		fmt.Printf("%-24s %-10s %#014x %#010x %8d  %s\n",
			s.Name, s.Type, s.Address, s.Offset, s.Size, stringsJoin(s.Flags))
	}
}

func printSegmentTable(segments []structure.Segment) {
	fmt.Printf("%-14s %-4s %-14s %-14s %10s %10s %6s\n",
		"TYPE", "FLAGS", "VADDR", "OFFSET", "FILESZ", "MEMSZ", "ALIGN")
	for _, s := range segments {
		fmt.Printf("%-14s %-4s %#014x %#014x %10d %10d %#6x\n",
			s.Type, s.Flags, s.VirtualAddr, s.Offset, s.FileSize, s.MemSize, s.Alignment)
	}
}

func printSymbolTable(syms []structure.Symbol) {
	if len(syms) == 0 {
		return // caller already printed the stripped-binary hint on stderr
	}
	fmt.Printf("%-18s %-8s %-7s %-16s %-8s %s\n", "VALUE", "SIZE", "SCOPE", "KIND", "DEFINED", "NAME")
	for _, s := range syms {
		fmt.Printf("%#018x %8d %-7s %-16s %-8t %s\n", s.Value, s.Size, s.Scope, s.Kind, s.Defined, s.Name)
	}
}

func stringsJoin(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}

// mapLoadErr distinguishes unsupported targets from ordinary failures at the
// exit-code layer (kept as a seam for future error typing).
func mapLoadErr(err error) error { return err }

// importGroup is the security-relevance bucket for imported symbols.
type importGroup struct {
	Category string   `json:"category"`
	Symbols  []string `json:"symbols"`
}

// classifyImports buckets imports by security relevance. Presence in a
// category is an observation only — never a vulnerability claim.
func classifyImports(imports []structure.Import) []importGroup {
	buckets := map[string][]string{}
	for _, im := range imports {
		if cat := class.Category(im.Name); cat != "" {
			buckets[cat] = append(buckets[cat], im.Name)
		}
	}
	cats := make([]string, 0, len(buckets))
	for k := range buckets {
		cats = append(cats, k)
	}
	sort.Strings(cats)
	out := make([]importGroup, 0, len(cats))
	for _, cat := range cats {
		names := dedupeStrings(buckets[cat])
		out = append(out, importGroup{Category: cat, Symbols: names})
	}
	return out
}

func uncategorizedNames(imports []structure.Import) []string {
	var out []string
	for _, im := range imports {
		if class.Category(im.Name) == "" {
			out = append(out, im.Name)
		}
	}
	sort.Strings(out)
	return dedupeStrings(out)
}

func dedupeStrings(in []string) []string {
	var out []string
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

func renderClassifiedImports(imports []structure.Import, groups []importGroup) {
	p := newPrinter()
	seen := map[string]bool{}
	for _, g := range groups {
		p.Info("ANALYSIS", fmt.Sprintf("%s (%d):", g.Category, len(g.Symbols)))
		for _, s := range g.Symbols {
			p.Info("ANALYSIS", "  "+s)
			seen[s] = true
		}
	}
	var rest []string
	for _, im := range imports {
		if !seen[im.Name] {
			rest = append(rest, im.Name)
		}
	}
	if len(rest) > 0 {
		sort.Strings(rest)
		p.Info("ANALYSIS", fmt.Sprintf("other (%d): %v", len(rest), rest))
	}
}

func printStringTable(classified []strscan.Classified) {
	for _, c := range classified {
		newPrinter().Info("ANALYSIS", fmt.Sprintf("[%s/%s] %q @ section=%s addr=0x%x",
			c.Class, c.Confidence, c.Value, c.Section, c.Address))
	}
}
