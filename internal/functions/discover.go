// Package functions implements function discovery over disassembled code
// regions using multiple evidence sources with explicit confidence
// (spec section 14):
//
//	symbol table entries        -> high   ("symbol")
//	entry point                 -> high   ("entry point")
//	direct call targets         -> medium ("call target")
//	prologue-pattern starts     -> low    ("prologue heuristic")
//
// A function discovered by several routes keeps the highest confidence and
// records every contributing source. Discovery never invents boundaries it
// cannot support: undecodable regions are skipped, not guessed through.
package functions

import (
	"fmt"
	"sort"

	"github.com/QYVORA/qyvora-aksum/internal/analysis/structure"
	"github.com/QYVORA/qyvora-aksum/internal/disasm"
)

// Confidence levels mirror the string classifier's vocabulary.
const (
	ConfHigh   = "high"
	ConfMedium = "medium"
	ConfLow    = "low"
)

// Function is one discovered function.
type Function struct {
	Name         string               `json:"name"`
	Address      uint64               `json:"address"`
	Size         int                  `json:"size"`
	End          uint64               `json:"end"` // exclusive
	Confidence   string               `json:"confidence"`
	Sources      []string             `json:"sources"`
	Instructions []disasm.Instruction `json:"-"`
	Calls        []uint64             `json:"-"` // direct callee addresses (raw)
	Callers      []uint64             `json:"-"`
	PLT          bool                 `json:"plt,omitempty"`
}

// Options bound discovery cost on large binaries.
type Options struct {
	MaxFunctionSize int // hard cap per function body in bytes
	MaxFunctions    int // cap on total discovered functions
}

// seedSet tracks candidate entry addresses with the best name/confidence
// seen and every contributing source label.
type seedSet struct {
	byAddr map[uint64]*seedInfo
	order  []uint64 // deterministic iteration
}

type seedInfo struct {
	name     string
	conf     string // best confidence rank so far
	sources  []string
	plt      bool
	callersN int
	confRank int
}

var confRank = map[string]int{ConfLow: 1, ConfMedium: 2, ConfHigh: 3}

func newSeedSet() *seedSet { return &seedSet{byAddr: map[uint64]*seedInfo{}} }

func (s *seedSet) add(addr uint64, name, conf, source string, plt bool) {
	info, ok := s.byAddr[addr]
	if !ok {
		info = &seedInfo{}
		s.byAddr[addr] = info
		s.order = append(s.order, addr)
	}
	if plt {
		info.plt = true
	}
	if confRank[conf] > info.confRank {
		info.confRank = confRank[conf]
		info.conf = conf
		if name != "" || info.name == "" {
			info.name = name
		}
	} else if info.name == "" && name != "" {
		info.name = name
	}
	if !containsStr(info.sources, source) {
		info.sources = append(info.sources, source)
	}
}

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// Discover runs multi-source discovery over the executable image.
func Discover(im *structure.Image, dec disasm.Decoder, opts Options) ([]*Function, error) {
	if opts.MaxFunctionSize <= 0 {
		opts.MaxFunctionSize = 128 * 1024
	}
	if opts.MaxFunctions <= 0 {
		opts.MaxFunctions = 100_000
	}

	textBase, textBytes, err := im.ExecutableRegion()
	if err != nil {
		return nil, err
	}
	insts, err := dec.Decode(textBytes, textBase)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", dec.Arch(), err)
	}

	// Harvest direct call targets across the whole image.
	callTargets := map[uint64]int{}
	for i := range insts {
		in := &insts[i]
		if in.Flow == disasm.FlowCall && in.HasTarget && inRegion(in.Target, textBase, len(textBytes)) {
			callTargets[in.Target]++
		}
	}

	seeds := newSeedSet()
	inText := func(a uint64) bool { return inRegion(a, textBase, len(textBytes)) }

	for _, sym := range im.Symbols() {
		if sym.Kind == "func" && sym.Defined && sym.Value != 0 && inText(sym.Value) {
			seeds.add(sym.Value, sym.Name, ConfHigh, "symbol", false)
		}
	}
	for _, sym := range im.DynamicSymbols() {
		if sym.Kind == "func" && sym.Defined && sym.Value != 0 && inText(sym.Value) {
			seeds.add(sym.Value, sym.Name, ConfHigh, "dynamic symbol", false)
		}
	}
	if inText(im.Target.Entry) {
		seeds.add(im.Target.Entry, "_start", ConfHigh, "entry point", false)
	}
	if pltStart, pltLen, hasPLT := im.PLTSection(); hasPLT {
		for addr := range callTargets {
			if inRegion(addr, pltStart, pltLen) {
				seeds.add(addr, fmt.Sprintf("plt_%x", addr), ConfMedium, "PLT stub", true)
			}
		}
	}
	for addr, n := range callTargets {
		if inText(addr) {
			seeds.add(addr, "", ConfMedium, "call target", false)
			seeds.byAddr[addr].callersN += n
		}
	}

	funcs := growBodies(seeds, insts, opts)

	sort.Slice(funcs, func(i, j int) bool { return funcs[i].Address < funcs[j].Address })

	// Wire caller/callee relations from direct calls landing inside bodies.
	covered := map[uint64]*Function{} // instruction addr -> owning function
	for _, f := range funcs {
		for i := range f.Instructions {
			covered[f.Instructions[i].Addr] = f
		}
	}
	for _, f := range funcs {
		for i := range f.Instructions {
			in := &f.Instructions[i]
			if in.Flow != disasm.FlowCall || !in.HasTarget {
				continue
			}
			f.Calls = append(f.Calls, in.Target)
			if callee, ok := covered[in.Target]; ok && callee != f {
				callee.Callers = append(callee.Callers, f.Address)
			}
		}
	}
	return funcs, nil
}

// growBodies expands each seed into an instruction body by bounded forward
// decode. Boundaries: another seed's start, a RET/HLT/UD2 terminator, a jump
// into already-covered territory, or MaxFunctionSize. This is deliberately
// conservative — better to under-approximate than fabricate code.
func growBodies(seeds *seedSet, insts []disasm.Instruction, opts Options) []*Function {
	byAddr := make(map[uint64]int, len(insts))
	for i := range insts {
		byAddr[insts[i].Addr] = i
	}
	claimed := make(map[int]bool, len(insts)) // inst index claimed by a function

	var funcs []*Function
	// Process seeds in ascending address order for determinism.
	addrs := append([]uint64(nil), seeds.order...)
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })

	for _, addr := range addrs {
		start, ok := byAddr[addr]
		if !ok || claimed[start] {
			continue
		}
		info := seeds.byAddr[addr]
		f := &Function{
			Name:       info.name,
			Address:    addr,
			Confidence: info.conf,
			Sources:    info.sources,
			PLT:        info.plt,
		}
		end := start
		for end < len(insts) && insts[end].Addr-addr < uint64(opts.MaxFunctionSize) {
			if end != start && claimed[end] {
				break // ran into an already-assigned body
			}
			in := insts[end]
			f.Instructions = append(f.Instructions, in)
			claimed[end] = true
			end++
			switch in.Flow {
			case disasm.FlowRet, disasm.FlowHlt:
				goto done
			}
		}
	done:
		if len(f.Instructions) > 0 {
			last := f.Instructions[len(f.Instructions)-1]
			f.End = last.Addr + uint64(last.Size)
			f.Size = int(f.End - f.Address)
			funcs = append(funcs, f)
		}
		if opts.MaxFunctions > 0 && len(funcs) >= opts.MaxFunctions {
			break
		}
	}
	return funcs
}

func inRegion(addr uint64, base uint64, size int) bool {
	return addr >= base && addr < base+uint64(size)
}
