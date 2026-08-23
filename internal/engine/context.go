// Package engine is aksum's shared analysis core: it owns the opened image,
// discovered functions, cross-references, and decoder for a target, plus the
// full static-assessment pipeline. Both the one-shot CLI commands and the
// interactive console drive this package so analysis logic exists exactly
// once and session state stays consistent.
package engine

import (
	"fmt"
	"sort"

	"github.com/QYVORA/qyvora-aksum/internal/disasm"
	x86dec "github.com/QYVORA/qyvora-aksum/internal/disasm/x86"
	"github.com/QYVORA/qyvora-aksum/internal/functions"
	strscan "github.com/QYVORA/qyvora-aksum/internal/analysis/strings"
	"github.com/QYVORA/qyvora-aksum/internal/analysis/structure"
	"github.com/QYVORA/qyvora-aksum/internal/binary"
	"github.com/QYVORA/qyvora-aksum/internal/security/class"
	"github.com/QYVORA/qyvora-aksum/internal/xrefs"
)

// UnsupportedError marks a validly invoked operation the current build
// genuinely cannot perform on this target (e.g. no decoder for the
// architecture). The CLI maps it to exit code 3.
type UnsupportedError struct{ Msg string }

func (e *UnsupportedError) Error() string { return e.Msg }

// Unsupportedf builds an UnsupportedError.
func Unsupportedf(format string, a ...any) error {
	return &UnsupportedError{Msg: fmt.Sprintf(format, a...)}
}

// DecoderFor returns a tested decoder for the target architecture, or an
// honest unsupported error for architectures without one yet.
func DecoderFor(arch binary.Arch) (disasm.Decoder, error) {
	switch arch {
	case "x86-64":
		return x86dec.New64(), nil
	case "x86":
		return x86dec.New32(), nil
	default:
		return nil, Unsupportedf("disassembly of %q is not supported yet (supported: x86-64, x86)", arch)
	}
}

// Context bundles an opened image with its discovered functions and
// cross-reference table — everything the code commands share.
type Context struct {
	Path    string
	Im      *structure.Image
	Target  *binary.Target
	Funcs   []*functions.Function
	Xrefs   *xrefs.Table
	Decoder disasm.Decoder

	strings []strscan.Classified // lazy cache of classified strings
}

// OpenAnalysis opens the image and runs discovery once for all consumers.
func OpenAnalysis(path string) (*Context, error) {
	im, err := structure.Open(path)
	if err != nil {
		return nil, err
	}
	dec, err := DecoderFor(im.Target.Arch)
	if err != nil {
		_ = im.Close()
		return nil, err
	}
	fn, err := functions.Discover(im, dec, functions.Options{})
	if err != nil {
		_ = im.Close()
		return nil, err
	}
	return &Context{
		Path:    path,
		Im:      im,
		Target:  im.Target,
		Funcs:   fn,
		Decoder: dec,
		Xrefs:   xrefs.Build(flattenInsts(fn), ownerMap(fn)),
	}, nil
}

// Close releases image resources.
func (c *Context) Close() error { return c.Im.Close() }

// ClassifiedStrings extracts and classifies strings once per context;
// later calls reuse the cached result.
func (c *Context) ClassifiedStrings() []strscan.Classified {
	if c.strings == nil {
		c.strings = strscan.ClassifyAll(strscan.Extract(c.Im.RawFile(), strscan.Options{}))
	}
	return c.strings
}

// StringAddresses returns the virtual addresses of extracted strings whose
// content contains substr (case-insensitive).
func (c *Context) StringAddresses(substr string) []uint64 {
	low := lower(substr)
	var out []uint64
	for _, s := range c.ClassifiedStrings() {
		if containsFold(s.Value, low) && s.Address != 0 {
			out = append(out, s.Address)
		}
	}
	return out
}

// ByAddr resolves the function starting at addr, if discovered.
func (c *Context) ByAddr(addr uint64) *functions.Function {
	for _, f := range c.Funcs {
		if f.Address == addr {
			return f
		}
	}
	return nil
}

// BySymbol resolves a function by display name.
func (c *Context) BySymbol(name string) *functions.Function {
	for _, f := range c.Funcs {
		if DisplayName(f) == name {
			return f
		}
	}
	return nil
}

// DisplayName returns a function's symbol name or an honest synthetic
// sub_<addr> label — aksum never invents names.
func DisplayName(f *functions.Function) string {
	if f.Name != "" {
		return f.Name
	}
	return fmt.Sprintf("sub_%x", f.Address)
}

// CallNames maps function addresses to their display names.
func CallNames(funcs []*functions.Function) map[uint64]string {
	m := make(map[uint64]string, len(funcs))
	for _, f := range funcs {
		m[f.Address] = DisplayName(f)
	}
	return m
}

func flattenInsts(funcs []*functions.Function) []disasm.Instruction {
	var out []disasm.Instruction
	for _, f := range funcs {
		out = append(out, f.Instructions...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

// ownerMap maps every instruction address to its owning function address.
func ownerMap(funcs []*functions.Function) map[uint64]uint64 {
	m := make(map[uint64]uint64)
	for _, f := range funcs {
		for i := range f.Instructions {
			m[f.Instructions[i].Addr] = f.Address
		}
	}
	return m
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func containsFold(s, sub string) bool {
	return len(sub) == 0 || containsBytes(lower(s), sub)
}

func containsBytes(s, sub string) bool {
	n := len(s) - len(sub)
	for i := 0; i <= n; i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ImportGroup buckets imports by security relevance. Membership is an
// observation of capability surface — never a vulnerability claim.
type ImportGroup struct {
	Category string   `json:"category"`
	Symbols  []string `json:"symbols"`
}

// ClassifyImports groups imported symbols by security-relevance category.
func ClassifyImports(imports []structure.Import) []ImportGroup {
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
	out := make([]ImportGroup, 0, len(cats))
	for _, cat := range cats {
		out = append(out, ImportGroup{Category: cat, Symbols: dedupeStrings(buckets[cat])})
	}
	return out
}

// UncategorizedImports lists imported symbols outside every known category.
func UncategorizedImports(imports []structure.Import) []string {
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
