package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	strscan "github.com/QYVORA/qyvora-aksum/internal/analysis/strings"
	"github.com/QYVORA/qyvora-aksum/internal/analysis/structure"
	"github.com/QYVORA/qyvora-aksum/internal/binary"
	"github.com/QYVORA/qyvora-aksum/internal/engine"
	"github.com/QYVORA/qyvora-aksum/internal/loader"
	"github.com/QYVORA/qyvora-aksum/internal/output"
)

// registerTargetCommands adds every command that takes a binary target.
// All share the same argument shape: <target> as the sole positional arg.
func registerTargetCommands(root *cobra.Command) {
	root.AddCommand(
		newBinaryCmd(),
		newPECmd(),
		newSectionsCmd(),
		newSegmentsCmd(),
		newSymbolsCmd(),
		newImportsCmd(),
		newStringsCmd(),
		newSurfaceCmd(),
	)
}

func oneArg(c *cobra.Command, args []string) (string, error) {
	if len(args) != 1 {
		return "", usagef("%s requires exactly one <target> argument", c.Name())
	}
	return args[0], nil
}

// loadTarget identifies a file via the format dispatch layer.
func loadTarget(path string) (*binary.Target, error) {
	return loader.Open(path)
}

// renderTarget prints the binary-identification property table.
func renderTarget(p *output.Printer, t *binary.Target) {
	p.Info("IDENTIFY", "Target identified")
	engine.RenderTargetProperties(os.Stdout, t)
}

func newBinaryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "binary <target>",
		Short: "Identify a binary and its security properties",
		Long: `Identify format, architecture, linking, and hardening properties
(PIE, NX, RELRO, stack canary, fortify) of the target file.

Values that cannot be determined from the file are reported as
"unknown" — never guessed.`,
		RunE: func(c *cobra.Command, args []string) error {
			path, err := oneArg(c, args)
			if err != nil {
				return err
			}
			t, err := loadTarget(path)
			if err != nil {
				return err
			}
			p := newPrinter()
			if p.Format() == "json" {
				return json.NewEncoder(os.Stdout).Encode(t)
			}
			renderTarget(p, t)
			return nil
		},
	}
}

func newSectionsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sections <target>",
		Short: "List ELF sections with addresses, sizes, permissions",
		RunE: func(c *cobra.Command, args []string) error {
			path, err := oneArg(c, args)
			if err != nil {
				return err
			}
			im, err := structure.Open(path)
			if err != nil {
				return mapLoadErr(err)
			}
			defer im.Close() //nolint:errcheck // read-only
			return emit(c, im.Sections())
		},
	}
}

func newSegmentsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "segments <target>",
		Short: "List program headers (segments) with rwx permissions",
		RunE: func(c *cobra.Command, args []string) error {
			path, err := oneArg(c, args)
			if err != nil {
				return err
			}
			im, err := structure.Open(path)
			if err != nil {
				return mapLoadErr(err)
			}
			defer im.Close() //nolint:errcheck // read-only
			return emit(c, im.Segments())
		},
	}
}

func newSymbolsCmd() *cobra.Command {
	var dynamic bool
	cmd := &cobra.Command{
		Use:   "symbols <target>",
		Short: "List symbols (static table; --dynamic for .dynsym)",
		RunE: func(c *cobra.Command, args []string) error {
			path, err := oneArg(c, args)
			if err != nil {
				return err
			}
			im, err := structure.Open(path)
			if err != nil {
				return mapLoadErr(err)
			}
			defer im.Close() //nolint:errcheck // read-only
			syms := im.Symbols()
			if dynamic {
				syms = im.DynamicSymbols()
			}
			if len(syms) == 0 && !dynamic && im.Target.Stripped == binary.PropertyEnabled {
				fmt.Fprintln(os.Stderr, "[!] no static symbol table (stripped); try --dynamic")
			}
			return emit(c, syms)
		},
	}
	cmd.Flags().BoolVar(&dynamic, "dynamic", false, "list .dynsym entries instead of .symtab")
	return cmd
}

func newImportsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "imports <target>",
		Short: "List imported functions grouped by security relevance",
		RunE: func(c *cobra.Command, args []string) error {
			path, err := oneArg(c, args)
			if err != nil {
				return err
			}
			im, err := structure.Open(path)
			if err != nil {
				return mapLoadErr(err)
			}
			defer im.Close() //nolint:errcheck // read-only
			imports := im.Imports()
			groups := engine.ClassifyImports(imports)
			if newPrinter().Format() == "json" {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{ //nolint:err113 // stable payload
					"total":         len(imports),
					"groups":        groups,
					"uncategorized": engine.UncategorizedImports(imports),
				})
			}
			engine.RenderImports(os.Stdout, imports)
			return nil
		},
	}
}

func newStringsCmd() *cobra.Command {
	var minLen int
	var utf16 bool
	var max int
	cmd := &cobra.Command{
		Use:   "strings <target>",
		Short: "Extract and security-classify embedded strings",
		RunE: func(c *cobra.Command, args []string) error {
			path, err := oneArg(c, args)
			if err != nil {
				return err
			}
			t, err := loader.Open(path)
			if err != nil {
				return mapLoadErr(err)
			}
			opts := strscan.Options{MinLength: minLen, UTF16: utf16, MaxStrings: max}
			var all []strscan.Str
			if t.Format == binary.FormatELF {
				im, err := structure.Open(path)
				if err != nil {
					return mapLoadErr(err)
				}
				defer im.Close() //nolint:errcheck // read-only
				all = strscan.Extract(im.RawFile(), opts)
			} else {
				// No container parser: degrade to a whole-file scan so the
				// strings command keeps its promise on RAW targets.
				data, err := os.ReadFile(path)
				if err != nil {
					return mapLoadErr(err)
				}
				all = strscan.ExtractRaw(data, opts)
			}
			classified := strscan.ClassifyAll(all)
			if newPrinter().Format() == "json" {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{ //nolint:err113 // stable payload
					"total":      len(all),
					"strings":    all,
					"classified": classified,
				})
			}
			p := newPrinter()
			p.Info("ANALYSIS", fmt.Sprintf("%d strings extracted, %d security-relevant", len(all), len(classified)))
			engine.RenderStrings(os.Stdout, classified)
			return nil
		},
	}
	cmd.Flags().IntVar(&minLen, "min-length", 4, "minimum string length")
	cmd.Flags().BoolVar(&utf16, "utf16", false, "also scan UTF-16LE runs")
	cmd.Flags().IntVar(&max, "max", 0, "cap reported strings (0 = unlimited)")
	return cmd
}
