package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	strscan "github.com/QYVORA/qyvora-aksum/internal/analysis/strings"
	"github.com/QYVORA/qyvora-aksum/internal/analysis/structure"
	"github.com/QYVORA/qyvora-aksum/internal/output"
	"github.com/QYVORA/qyvora-aksum/internal/surface"
)

func newSurfaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "surface <target>",
		Short: "Summarize the binary's externally observable attack surface",
		Long: `Aggregates entry points, security-relevant imported APIs grouped
by category, exported functions, and classified strings into one
surface view.

Every number is an observation traced to a concrete extraction; the
report contains no risk scores or guesses.`,
		RunE: func(c *cobra.Command, args []string) error {
			path, err := oneArg(c, args)
			if err != nil {
				return err
			}
			im, err := structure.Open(path)
			if err != nil {
				return err
			}
			defer im.Close() //nolint:errcheck // read-only

			extracted := strscan.Extract(im.RawFile(), strscan.Options{})
			rep := surface.Build(im.Target, im, im.Exports(), strscan.ClassifyAll(extracted))

			p := newPrinter()
			if p.Format() == "json" {
				return json.NewEncoder(os.Stdout).Encode(rep)
			}
			renderSurface(p, rep)
			return nil
		},
	}
	return cmd
}

func renderSurface(p *output.Printer, r *surface.Report) {
	t := r.Target
	p.Info("SURFACE", fmt.Sprintf("Target: %s (%s/%s)", t.Path, t.Format, t.Arch))
	p.Info("SURFACE", fmt.Sprintf("Imports: %d total, %d security-relevant; exported functions: %d; classified strings: %d",
		r.TotalImports, r.RiskyImports, r.ExportFuncs, r.SurfaceStrs))

	if len(r.Categories) > 0 {
		fmt.Println("\nSECURITY-RELEVANT IMPORT CATEGORIES")
		for _, cat := range r.Categories {
			names := cat.Names
			sort.Strings(names)
			limit := names
			if len(limit) > 8 {
				limit = append(append([]string{}, limit[:8]...), "…")
			}
			fmt.Printf("  %-18s %3d  %s\n", cat.Category, cat.Count, joinLimit(limit))
		}
	}

	if len(r.EntryPoints) > 0 {
		fmt.Println("\nENTRY POINTS (entry + first exported functions)")
		for _, e := range r.EntryPoints {
			if e.Kind == "export-func" && e.Addr != 0 {
				fmt.Printf("  export-func  %-32s %#x\n", e.Name, e.Addr)
			} else if e.Kind == "export-func" {
				fmt.Printf("  export-func  %s\n", e.Name)
			} else {
				fmt.Printf("  entry        %-32s %#x\n", e.Name, e.Addr)
			}
		}
	}

	if len(r.StringClasses) > 0 {
		fmt.Println("\nSTRING CLASSES")
		keys := make([]string, 0, len(r.StringClasses))
		for k := range r.StringClasses {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %-18s %3d\n", k, r.StringClasses[k])
		}
	}
}

func joinLimit(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
