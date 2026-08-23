package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	strscan "github.com/QYVORA/qyvora-aksum/internal/analysis/strings"
	"github.com/QYVORA/qyvora-aksum/internal/analysis/structure"
	"github.com/QYVORA/qyvora-aksum/internal/engine"
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
	engine.RenderSurface(os.Stdout, r)
}
