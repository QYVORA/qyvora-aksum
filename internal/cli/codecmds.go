package cli

import (
	"fmt"
	"sort"
	"strings"

	strscan "github.com/QYVORA/qyvora-aksum/internal/analysis/strings"
	"github.com/QYVORA/qyvora-aksum/internal/analysis/structure"
	"github.com/QYVORA/qyvora-aksum/internal/binary"
	"github.com/QYVORA/qyvora-aksum/internal/disasm"
	x86dec "github.com/QYVORA/qyvora-aksum/internal/disasm/x86"
	"github.com/QYVORA/qyvora-aksum/internal/functions"
	"github.com/QYVORA/qyvora-aksum/internal/xrefs"
)

// decoderFor returns a tested decoder for the target architecture, or an
// honest unsupported error for architectures without one yet. Unsupported
// architectures are a usage-class failure (exit 3 via Unsupported).
func decoderFor(arch binary.Arch) (disasm.Decoder, error) {
	switch arch {
	case "x86-64":
		return x86dec.New64(), nil
	case "x86":
		return x86dec.New32(), nil
	default:
		return nil, fmt.Errorf("disassembly of %q is not supported yet (supported: x86-64, x86)", arch)
	}
}

// analysisContext bundles an opened image with its discovered functions and
// cross-reference table — everything the code commands share.
type analysisContext struct {
	im      *structure.Image
	funcs   []*functions.Function
	xr      *xrefs.Table
	decoder disasm.Decoder
}

// openAnalysis opens the image and runs discovery once for all code commands.
func openAnalysis(path string) (*analysisContext, error) {
	im, err := structure.Open(path)
	if err != nil {
		return nil, err
	}
	dec, err := decoderFor(im.Target.Arch)
	if err != nil {
		_ = im.Close()
		return nil, unsupportedf("%s", err)
	}
	fn, err := functions.Discover(im, dec, functions.Options{})
	if err != nil {
		_ = im.Close()
		return nil, err
	}
	ac := &analysisContext{
		im:      im,
		funcs:   fn,
		decoder: dec,
		xr:      xrefs.Build(flattenInsts(fn), ownerMap(fn)),
	}
	return ac, nil
}

// Close releases image resources.
func (a *analysisContext) Close() { _ = a.im.Close() }

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

// stringAddresses returns the virtual addresses of extracted strings whose
// content contains substr (case-insensitive).
func (a *analysisContext) stringAddresses(substr string) ([]uint64, error) {
	strs := strscan.Extract(a.im.RawFile(), strscan.Options{})
	low := strings.ToLower(substr)
	var out []uint64
	for _, s := range strs {
		if strings.Contains(strings.ToLower(s.Value), low) && s.Address != 0 {
			out = append(out, s.Address)
		}
	}
	return out, nil
}
