package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-aksum/internal/engine"
	"github.com/QYVORA/qyvora-aksum/internal/formats/pe"
	"github.com/QYVORA/qyvora-aksum/internal/table"
)

func newPECmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pe <target>",
		Short: "Identify a PE image and enumerate sections and imports",
		Long: `Parses a Windows Portable Executable (PE32/PE32+) image: MZ and PE
signatures, COFF machine/characteristics, optional-header class and entry
point, the section table, and the import table (named and ordinal).

Every value is read directly from the file; undeterminable fields are left
out rather than guessed. Non-PE files are refused with a clear error.`,
		RunE: func(c *cobra.Command, args []string) error {
			path, err := oneArg(c, args)
			if err != nil {
				return err
			}
			f, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("open %s: %w", path, err)
			}
			defer f.Close() //nolint:errcheck // read-only
			st, err := f.Stat()
			if err != nil {
				return fmt.Errorf("stat %s: %w", path, err)
			}
			pf, err := pe.Open(f, st.Size())
			if err != nil {
				return usagef("%s is not a recognized PE image: %v", path, err)
			}
			pf.Target.Path = path
			pf.Target.Size = st.Size()

			p := newPrinter()
			if p.Format() == "json" {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{
					"target":   pf.Target,
					"sections": pf.Sections(),
					"imports":  pf.Imports(),
					"needed":   pf.Needed(),
				})
			}

			p.Info("PE", fmt.Sprintf("Target: %s (%s/%s)", path, pf.Target.Class, pf.Target.Arch))
			engine.RenderTargetProperties(os.Stdout, pf.Target)
			renderPESections(pf.Sections())
			renderPEImports(pf.Imports())
			return nil
		},
	}
}

func renderPESections(secs []pe.Section) {
	fmt.Printf("\nSECTIONS (%d)\n", len(secs))
	t := table.New("name", "vaddr", "vsize", "offset", "rsize", "flags").
		SetAlign(1, table.AlignRight).SetAlign(2, table.AlignRight).
		SetAlign(3, table.AlignRight).SetAlign(4, table.AlignRight)
	for _, s := range secs {
		t.AddRow(s.Name, engine.Addr(s.Virtual), fmt.Sprintf("%#x", s.VSize),
			engine.Addr(s.Offset), fmt.Sprintf("%#x", s.RSize), strings.Join(s.Flags, " "))
	}
	t.Render(os.Stdout)
}

func renderPEImports(imps []pe.Import) {
	fmt.Printf("\nIMPORTS (%d)\n", len(imps))
	t := table.New("library", "name")
	for _, im := range imps {
		name := im.Name
		if name == "" {
			name = fmt.Sprintf("ordinal %d", im.Ordinal)
		}
		t.AddRow(im.Library, name)
	}
	t.Render(os.Stdout)
}
