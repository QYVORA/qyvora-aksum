package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	strscan "github.com/QYVORA/qyvora-aksum/internal/analysis/strings"
	"github.com/QYVORA/qyvora-aksum/internal/analysis/structure"
	"github.com/QYVORA/qyvora-aksum/internal/binary"
	"github.com/QYVORA/qyvora-aksum/internal/loader"
	"github.com/QYVORA/qyvora-aksum/internal/output"
)

// registerTargetCommands adds every command that takes a binary target.
// All share the same argument shape: <target> as the sole positional arg.
func registerTargetCommands(root *cobra.Command) {
	root.AddCommand(
		newBinaryCmd(),
		newSectionsCmd(),
		newSegmentsCmd(),
		newSymbolsCmd(),
		newImportsCmd(),
		newStringsCmd(),
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

func prop(name string, v binary.Property) string {
	switch v {
	case binary.PropertyEnabled:
		return name + ": Enabled"
	case binary.PropertyDisabled:
		return name + ": Disabled"
	default:
		return name + ": Unknown"
	}
}

func symbolsProp(stripped binary.Property) string {
	// The user-facing question is "are symbols present?" while Target stores
	// "stripped"; invert for display.
	switch stripped {
	case binary.PropertyEnabled:
		return "Symbols: Stripped"
	case binary.PropertyDisabled:
		return "Symbols: Present"
	default:
		return "Symbols: Unknown"
	}
}

func renderTarget(p *output.Printer, t *binary.Target) {
	p.Info("IDENTIFY", "Target: "+t.Path)
	if t.Format == binary.FormatRaw {
		p.Info("IDENTIFY", "Format: unknown container (no parser); strings analysis only")
		return
	}
	p.Info("IDENTIFY", "Format: "+t.Class+" ("+t.Type+")")
	p.Info("IDENTIFY", "Architecture: "+string(t.Arch))
	p.Info("IDENTIFY", "Endianness: "+string(t.Endianness))
	p.Info("IDENTIFY", "OS/ABI: "+t.OSType)
	p.Info("IDENTIFY", fmt.Sprintf("Entry point: %#x", t.Entry))
	p.Info("IDENTIFY", "Linking: "+string(t.Linking))
	p.Info("IDENTIFY", prop("PIE", t.PIE))
	p.Info("IDENTIFY", prop("NX", t.NX))
	p.Info("IDENTIFY", "RELRO: "+t.RELRO)
	p.Info("IDENTIFY", prop("Canary", t.Canary))
	p.Info("IDENTIFY", prop("Fortify", t.Fortify))
	p.Info("IDENTIFY", symbolsProp(t.Stripped))
	if t.Interpreter != "" {
		p.Info("IDENTIFY", "Interpreter: "+t.Interpreter)
	}
	for _, lib := range t.Needed {
		p.Info("IDENTIFY", "Library: "+lib)
	}
	if t.BuildID != "" {
		p.Info("IDENTIFY", "Build ID: "+t.BuildID)
	}
	for _, h := range t.CompilerHints {
		p.Info("IDENTIFY", "Hint: "+h)
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
			groups := classifyImports(imports)
			if newPrinter().Format() == "json" {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{
					"total":     len(imports),
					"groups":    groups,
					"uncategorized": uncategorizedNames(imports),
				})
			}
			renderClassifiedImports(imports, groups)
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
			im, err := structure.Open(path)
			if err != nil {
				return mapLoadErr(err)
			}
			defer im.Close() //nolint:errcheck // read-only
			all := strscan.Extract(im.RawFile(), strscan.Options{MinLength: minLen, UTF16: utf16, MaxStrings: max})
			classified := strscan.ClassifyAll(all)
			if newPrinter().Format() == "json" {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{
					"total":      len(all),
					"strings":    all,
					"classified": classified,
				})
			}
			p := newPrinter()
			p.Info("ANALYSIS", fmt.Sprintf("%d strings extracted, %d security-relevant", len(all), len(classified)))
			printStringTable(classified)
			return nil
		},
	}
	cmd.Flags().IntVar(&minLen, "min-length", 4, "minimum string length")
	cmd.Flags().BoolVar(&utf16, "utf16", false, "also scan UTF-16LE runs")
	cmd.Flags().IntVar(&max, "max", 0, "cap reported strings (0 = unlimited)")
	return cmd
}
