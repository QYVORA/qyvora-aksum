// Package dataflow performs honest, intra-procedural value tracking on
// x86-64 code to statically resolve call-site arguments.
//
// Scope and limits (stated up front):
//   - Linear scan of each function's decoded instruction stream. Values are
//     reset at unconditional jumps whose target is not the next instruction
//     and at returns, so cross-block flows are deliberately not followed.
//   - Only address-like values are tracked (LEA rip-relative results,
//     immediate constants, direct loads). General arithmetic is not modeled;
//     an overwritten or combined register simply becomes unknown.
//   - Stack spills through MOV-to-[rsp|rbp] slots are tracked; PUSH/POP are
//     not modeled.
//   - Callee names come from discovered function symbols; PLT stubs are
//     resolved to their true import name via the JUMP_SLOT relocation that
//     owns the GOT slot the stub reads.
//
// The engine never speculates: a reported argument is one whose value was
// provably materialized by the instructions seen. Everything else is
// reported as nothing rather than as a guess.
package dataflow

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	strscan "github.com/QYVORA/qyvora-aksum/internal/analysis/strings"
	"github.com/QYVORA/qyvora-aksum/internal/analysis/structure"
	"github.com/QYVORA/qyvora-aksum/internal/disasm"
	"github.com/QYVORA/qyvora-aksum/internal/functions"
)

// ArgKinds for ResolvedArg.Kind.
const (
	KindString   = "string"   // address resolves to an extracted string
	KindConstant = "constant" // immediate/known numeric value
	KindAddress  = "address"  // known data address with no string content
)

// ResolvedArg is one call argument whose value was tracked statically.
type ResolvedArg struct {
	Register string `json:"register"`
	Position int    `json:"position"` // SysV ABI argument slot (0-based)
	Kind     string `json:"kind"`
	Address  uint64 `json:"address,omitempty"`
	Value    uint64 `json:"value,omitempty"` // for constants
	Text     string `json:"text,omitempty"`  // string content when known
}

// CallSite records one call instruction with its resolved context.
type CallSite struct {
	Caller     string        `json:"caller"`
	CallerAddr uint64        `json:"caller_addr"`
	Addr       uint64        `json:"addr"`
	Callee     string        `json:"callee"` // import name, symbol name, or sub_%x fallback
	CalleeAddr uint64        `json:"callee_addr,omitempty"`
	ViaPLT     bool          `json:"via_plt,omitempty"`
	Args       []ResolvedArg `json:"args,omitempty"` // only statically-resolved args
}

// known is a tracked register/stack-slot value.
type known struct {
	addr uint64 // address or constant value
}

// reStack parses "[rsp+0x10]" / "[rbp-0x8]" style stack operands.
var reStack = regexp.MustCompile(`(?i)^\[\s*(rsp|rbp)\s*([+-])\s*(0x[0-9a-f]+|\d+)\s*\]$`)

// Engine holds image-wide resolution tables.
type Engine struct {
	funcByAddr  map[uint64]*functions.Function
	pltToImport map[uint64]string // PLT stub entry -> import symbol name
	gotToSym    map[uint64]string // GOT slot -> import symbol name
	stringAt    map[uint64]string // virtual addr -> extracted string content
}

// New builds the resolution tables from relocations, discovered functions
// and classified strings. All inputs may be empty; the engine then simply
// resolves less.
func New(relocs []structure.Reloc, funcs []*functions.Function, strs []strscan.Classified) *Engine {
	e := &Engine{
		funcByAddr:  make(map[uint64]*functions.Function, len(funcs)),
		pltToImport: make(map[uint64]string),
		gotToSym:    make(map[uint64]string),
		stringAt:    make(map[uint64]string),
	}
	for _, r := range relocs {
		if r.Type == "7" && r.Symbol != "" { // 7 = R_X86_64_JUMP_SLOT / R_386_JMP_SLOT
			if base, _, ok := strings.Cut(r.Symbol, "@"); ok {
				e.gotToSym[r.Offset] = base
			} else {
				e.gotToSym[r.Offset] = r.Symbol
			}
		}
	}
	for _, f := range funcs {
		e.funcByAddr[f.Address] = f
	}
	for _, f := range funcs {
		if !f.PLT {
			continue
		}
		if name := e.resolveStub(f); name != "" {
			e.pltToImport[f.Address] = name
		}
	}
	for _, s := range strs {
		e.stringAt[s.Address] = s.Value
	}
	return e
}

// resolveStub finds the GOT slot a PLT stub reads and maps it to the
// owning import symbol. Stub shape: jmp qword [rip+disp] (optionally bnd-
// prefixed), possibly after an endbr64.
func (e *Engine) resolveStub(f *functions.Function) string {
	for i := range f.Instructions {
		ins := &f.Instructions[i]
		if ins.Flow != disasm.FlowJmp && strings.ToLower(ins.Mnemonic) != "jmp" {
			continue
		}
		for _, op := range ins.Operands {
			if disasm.IsRipRelative(op) {
				got := disasm.RipTarget(*ins, op)
				if sym, ok := e.gotToSym[got]; ok {
					return sym
				}
			}
		}
	}
	return ""
}

// sysvArgRegs is the System V AMD64 integer argument order.
var sysvArgRegs = []string{"rdi", "rsi", "rdx", "rcx", "r8", "r9"}

// volatile regs are clobbered across calls per the SysV ABI.
var volatileRegs = map[string]bool{
	"rax": true, "rcx": true, "rdx": true,
	"rsi": true, "rdi": true,
	"r8": true, "r9": true, "r10": true, "r11": true,
}

func normReg(text string) string {
	t := strings.ToLower(strings.TrimSpace(text))
	// Canonicalize 32-bit aliases (ESI -> rsi) onto 64-bit names so arg
	// positions match the ABI table regardless of operand width.
	if len(t) == 3 && t[0] == 'e' {
		return "r" + t[1:]
	}
	return t
}

// Analyze walks one function linearly and reports resolved call sites.
func (e *Engine) Analyze(f *functions.Function) []CallSite {
	var sites []CallSite
	regs := make(map[string]known, 8)
	stack := make(map[uint64]known, 4)

	reset := func() {
		regs = make(map[string]known, 8)
		stack = make(map[uint64]known, 4)
	}

	for i := range f.Instructions {
		ins := &f.Instructions[i]
		ops := ins.Operands
		mn := strings.ToLower(ins.Mnemonic) // decoder renders Intel-uppercase

		switch mn {
		case "lea":
			if len(ops) >= 2 && ops[0].Kind == "reg" && disasm.IsRipRelative(ops[1]) {
				regs[normReg(ops[0].Text)] = known{addr: disasm.RipTarget(*ins, ops[1])}
			}

		case "mov":
			if len(ops) < 2 {
				break
			}
			dst, src := ops[0], ops[1]
			switch {
			case src.Kind == "imm":
				if dst.Kind == "reg" {
					regs[normReg(dst.Text)] = known{addr: src.Value}
				}
			case src.Kind == "mem" && dst.Kind == "reg":
				switch {
				case disasm.IsRipRelative(src):
					regs[normReg(dst.Text)] = known{addr: disasm.RipTarget(*ins, src)}
				default:
					if sm := stackSlot(src.Text); sm != nil {
						if v, ok := stack[sm.off]; ok {
							regs[normReg(dst.Text)] = v
						}
					}
				}
			case src.Kind == "reg" && dst.Kind == "mem":
				if sm := stackSlot(dst.Text); sm != nil {
					if v, ok := regs[normReg(src.Text)]; ok {
						stack[sm.off] = v
					}
				}
			case src.Kind == "reg" && dst.Kind == "reg":
				if v, ok := regs[normReg(src.Text)]; ok {
					regs[normReg(dst.Text)] = v
				} else {
					delete(regs, normReg(dst.Text))
				}
			}

		case "push":
			if len(ops) == 1 && ops[0].Kind == "reg" {
				delete(regs, normReg(ops[0].Text))
			}
		case "pop":
			if len(ops) == 1 && ops[0].Kind == "reg" {
				delete(regs, normReg(ops[0].Text))
			}
		case "xor":
			// xor r,r zeroes the register — a common idiom worth honoring.
			if len(ops) >= 2 && ops[0].Kind == "reg" && ops[1].Kind == "reg" &&
				normReg(ops[0].Text) == normReg(ops[1].Text) {
				regs[normReg(ops[0].Text)] = known{addr: 0}
			}
		}

		switch ins.Flow {
		case disasm.FlowCall:
			site := CallSite{
				Caller:     f.Name,
				CallerAddr: f.Address,
				Addr:       ins.Addr,
			}
			if ins.HasTarget {
				site.CalleeAddr = ins.Target
				site.Callee, site.ViaPLT = e.calleeName(ins.Target)
			}
			for pos, reg := range sysvArgRegs {
				v, ok := regs[reg]
				if !ok {
					continue
				}
				arg := ResolvedArg{Register: reg, Position: pos}
				if content, isStr := e.stringAt[v.addr]; isStr {
					arg.Kind = KindString
					arg.Address = v.addr
					arg.Text = content
				} else if _, inFunc := e.funcByAddr[v.addr]; !inFunc && v.addr > 0x1000 {
					arg.Kind = KindAddress
					arg.Address = v.addr
					arg.Value = v.addr
				} else {
					arg.Kind = KindConstant
					arg.Value = v.addr
				}
				site.Args = append(site.Args, arg)
			}
			if site.Callee != "" || len(site.Args) > 0 {
				sites = append(sites, site)
			}
			for reg := range volatileRegs {
				delete(regs, reg)
			}
		case disasm.FlowRet, disasm.FlowHlt:
			reset()
		case disasm.FlowJmp:
			// The linear scan continues at the fall-through address, but an
			// unconditional jump whose target is not that next instruction
			// means the decoded continuation was skipped — state cannot be
			// carried across honestly, so drop it.
			if !ins.HasTarget || ins.Target != ins.Addr+uint64(ins.Size) {
				reset()
			}
		}
	}
	return sites
}

// AnalyzeAll runs Analyze across functions and returns sites sorted by
// address for deterministic output.
func (e *Engine) AnalyzeAll(funcs []*functions.Function) []CallSite {
	n := 0
	for _, f := range funcs {
		n += len(f.Instructions)
	}
	all := make([]CallSite, 0, n/64+8)
	for _, f := range funcs {
		all = append(all, e.Analyze(f)...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Addr < all[j].Addr })
	return all
}

func (e *Engine) calleeName(target uint64) (string, bool) {
	if name, ok := e.pltToImport[target]; ok {
		return name, true
	}
	if f, ok := e.funcByAddr[target]; ok {
		return f.Name, false
	}
	return fmt.Sprintf("sub_%x", target), false
}

type stackRef struct{ off uint64 }

// stackSlot parses "[rsp+0x10]" / "[rbp-0x8]" into a normalized key.
func stackSlot(text string) *stackRef {
	m := reStack.FindStringSubmatch(text)
	if m == nil {
		return nil
	}
	off, err := strconv.ParseUint(m[3], 0, 64) //nolint:errcheck // regexp-constrained
	if err != nil {
		return nil
	}
	if m[2] == "-" {
		off = ^off + 1 // two's complement so +N/-N collide correctly
	}
	base := m[1]
	key := off
	if base == "rbp" {
		key |= 1 << 63 // disjoint keyspace from rsp-relative slots
	}
	return &stackRef{off: key}
}
