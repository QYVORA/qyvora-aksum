package engine

import (
	"fmt"
	"sort"

	"github.com/QYVORA/qyvora-aksum/internal/cfg"
	"github.com/QYVORA/qyvora-aksum/internal/functions"
)

// CFGReport summarizes one function's control-flow graph.
type CFGReport struct {
	Function    string      `json:"function"`
	Address     uint64      `json:"address"`
	Metrics     cfg.Stats   `json:"metrics"`
	Unreachable []uint64    `json:"unreachable_blocks,omitempty"`
	Blocks      []cfg.Block `json:"blocks,omitempty"`
}

// BuildCFGReports computes per-function CFG metrics for every discovered
// function (or only fnName when given), including block detail on request.
func BuildCFGReports(c *Context, fnName string, blocks bool) ([]CFGReport, error) {
	targets := c.Funcs
	if fnName != "" {
		f := c.BySymbol(fnName)
		if f == nil {
			return nil, fmt.Errorf("no function named %q", fnName)
		}
		targets = []*functions.Function{f}
	}
	reports := make([]CFGReport, 0, len(targets))
	for _, f := range targets {
		g := cfg.Build(f.Address, f.Instructions)
		r := CFGReport{Function: DisplayName(f), Address: f.Address, Metrics: g.Metrics()}
		if g.Loops > 0 || len(g.Unreachable) > 0 {
			r.Unreachable = g.Unreachable
		}
		if blocks {
			ordered := make([]*cfg.Block, 0, len(g.ByAddr))
			for _, b := range g.ByAddr {
				ordered = append(ordered, b)
			}
			sort.Slice(ordered, func(i, j int) bool { return ordered[i].Start < ordered[j].Start })
			for _, b := range ordered {
				r.Blocks = append(r.Blocks, *b)
			}
		}
		reports = append(reports, r)
	}
	return reports, nil
}
