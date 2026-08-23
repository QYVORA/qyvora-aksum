package engine

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/QYVORA/qyvora-aksum/internal/disasm"
	"github.com/QYVORA/qyvora-aksum/internal/functions"
)

// DisasmRow is one rendered instruction line for tabular/listing output.
type DisasmRow struct {
	Addr     uint64 `json:"address"`
	Bytes    string `json:"bytes"`
	Mnemonic string `json:"mnemonic"`
	Operands string `json:"operands"`
}

// SelectInstructions resolves the instructions for a disassembly request:
//
//	""          -> linear decode of the executable region
//	"0x401000"  -> the discovered function starting at that address
//	"name"      -> the function with that display name
//
// limit caps the returned rows (0 = unlimited).
func SelectInstructions(c *Context, selector string, limit int) ([]disasm.Instruction, string, error) {
	var insts []disasm.Instruction
	var header string
	var err error
	switch {
	case selector == "":
		base, bytes, rerr := c.Im.ExecutableRegion()
		if rerr != nil {
			return nil, "", rerr
		}
		insts, err = c.Decoder.Decode(bytes, base)
		if err != nil {
			return nil, "", err
		}
		header = fmt.Sprintf("executable region (%d instructions)", len(insts))
	case isHexAddr(selector):
		addr, _ := strconv.ParseUint(strings.TrimPrefix(selector, "0x"), 16, 64)
		f := c.ByAddr(addr)
		if f == nil {
			return nil, "", fmt.Errorf("no discovered function starts at %s (see 'functions')", Addr(addr))
		}
		insts, header = f.Instructions, functionHeader(f)
	default:
		f := c.BySymbol(selector)
		if f == nil {
			return nil, "", fmt.Errorf("no function named %q (see 'functions')", selector)
		}
		insts, header = f.Instructions, functionHeader(f)
	}
	if limit > 0 && len(insts) > limit {
		insts = insts[:limit]
		header += fmt.Sprintf(" — truncated at %d instructions", limit)
	}
	return insts, header, nil
}

func functionHeader(f *functions.Function) string {
	return fmt.Sprintf("function %s at %#x (%d bytes)", DisplayName(f), f.Address, f.Size)
}

func isHexAddr(s string) bool {
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}

// RenderDisasm writes a listing: header comment line then one row per
// instruction in fixed-width columns (listings are not tables by design).
func RenderDisasm(w interface{ Write([]byte) (int, error) }, header string, insts []disasm.Instruction) {
	fmt.Fprintf(w, "; %s\n", header)
	for i := range insts {
		in := &insts[i]
		fmt.Fprintf(w, "%#08x  %-22s %s %s\n",
			in.Addr, hexBytes(in.Bytes), in.Mnemonic, joinOperands(in))
	}
}

func hexBytes(b []byte) string {
	var sb strings.Builder
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%02x", x)
	}
	return sb.String()
}

func joinOperands(in *disasm.Instruction) string {
	out := make([]string, len(in.Operands))
	for i, op := range in.Operands {
		out[i] = op.Text
	}
	return strings.Join(out, ", ")
}
