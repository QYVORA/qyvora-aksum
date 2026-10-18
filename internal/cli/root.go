// Package aksumcli wires the aksum command tree, shared flags, exit-code
// handling, and cancellation. Execute never calls os.Exit so callers control
// process termination.
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-aksum/internal/exitcode"
	"github.com/QYVORA/qyvora-aksum/internal/version"
)

// usageError marks a mistake in how aksum was invoked (unknown flag/command,
// invalid value, missing argument). It maps to exit code 2.
type usageError struct{ err error }

func (u usageError) Error() string { return u.err.Error() }
func (u usageError) Unwrap() error { return u.err }

func usagef(format string, a ...any) error {
	return usageError{fmt.Errorf(format, a...)}
}

// unsupportedError marks a validly invoked operation the current build
// genuinely cannot perform on this target (e.g. no decoder for the
// architecture). It maps to exit code 3 per the aksum contract.
type unsupportedError struct{ msg string }

func unsupportedf(format string, a ...any) error {
	return unsupportedError{fmt.Sprintf(format, a...)}
}

func (u unsupportedError) Error() string { return u.msg }

var (
	updateFlag    bool
	formatFlag    string
	quietFlag     bool
	eventsFlag    string
	allowShellOut bool
)

// Execute runs the root command against os.Args and returns the exit code.
// The caller owns process termination.
func Execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return ExecuteArgsContext(ctx, os.Args[1:])
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "aksum",
		Short: "Binary security assessment & reverse-engineering platform",
		Long: `aksum is a terminal-first binary-security assessment platform.

Commands follow the shared tier grammar
<tool> <tier> <module> [<action>] [target] [flags]: every analysis module
lives under the recon tier. Run it with no arguments to print this help;
analysis is one-shot, e.g. aksum recon analyze <target>,
aksum recon strings <target>, aksum recon imports <target>.

It identifies a binary, enumerates its structure (sections, segments,
symbols, imports), analyzes strings and code, discovers functions,
builds call/control-flow graphs, classifies security-relevant APIs,
maps attack surface, and reports candidate weaknesses as evidence-
backed findings with explicit confidence.

Authorized use only: analyze software you own or are authorized to
assess.`,
		Example: `  aksum recon analyze ./sample.bin
  aksum recon strings ./sample.bin --min-length 6
  aksum recon symbols ./sample.bin --output json
  aksum recon dynamic plan ./sample.bin
  aksum recon functions ./sample.bin --min-confidence high`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Version,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if formatFlag != "" && formatFlag != "terminal" && formatFlag != "json" {
				return usagef("invalid output format %q (terminal, json)", formatFlag)
			}
			if eventsFlag != "" && eventsFlag != "stdout" && eventsFlag != "stderr" {
				// File paths are allowed too; validate creatable lazily per command.
				if eventsFlag[0] == '-' {
					return usagef("invalid --events value %q (stdout, stderr, or file path)", eventsFlag)
				}
			}
			if eventsFlag == "stdout" && formatFlag == "json" {
				// stdout must carry exactly one machine stream. With the event
				// JSONL stream owning stdout, the JSON report cannot share it:
				// use --events stderr, --events <file>, or --report <file>.
				return usagef("cannot combine --events stdout with --output json (one machine stream per descriptor); use --events stderr, --events <file>, or --report <path>")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return usagef("unknown command %q (try 'aksum --help')", args[0])
			}
			// The bare invocation is one-shot CLI only: print usage rather
			// than drop into an interactive interface. The per-tool TUI is
			// disabled pending the redirect of qyvora-tui to the future AI
			// orchestration layer.
			return cmd.Root().Help()
		},
		// Unknown subcommands are usage errors (exit 2).
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return usagef("unknown command %q (try 'aksum --help')", args[0])
			}
			return nil
		},
	}

	pf := root.PersistentFlags()
	pf.BoolVar(&updateFlag, "update", false, "update the CLI to the latest official release")
	// -o/--output is the flag the shared conformance layer drives every
	// framework with ("version -o json"). --format/-f is kept as an alias so
	// existing aksum callers and scripts keep working; both write the same
	// variable, so whichever appears last on the command line wins.
	pf.StringVarP(&formatFlag, "output", "o", "", "output format: terminal, json")
	pf.StringVarP(&formatFlag, "format", "f", "", "output format: terminal, json (alias for --output)")
	pf.BoolVarP(&quietFlag, "quiet", "q", false, "suppress non-error terminal output")
	pf.StringVar(&eventsFlag, "events", "", "emit JSONL event stream to stdout, stderr, or a file path")
	pf.BoolVar(&allowShellOut, "allow-shellout", false, "allow scripts to use exec/run.cmd shell-out (also via QYVORA_ALLOW_SHELLOUT=1)")

	root.SetVersionTemplate(fmt.Sprintf("aksum %s\n", version.Version))
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageError{err}
	})

	root.AddCommand(newVersionCmd(), newUpdatesCmd(), newCapabilitiesCmd(), newScriptCmd())

	// Tier grammar: <tool> <tier> <module> [<action>] [target] [flags].
	// aksum is a read-only analysis platform, so every module lives under
	// recon. The exploit and report tiers always exist so the command shape
	// is uniform across tools; each explains its own emptiness instead of
	// rendering as a blank parent.
	recon := &cobra.Command{
		Use:   "recon",
		Short: "binary discovery and analysis modules",
	}
	recon.AddCommand(newAnalyzeCmd(), newDynamicCmd())
	registerTargetCommands(recon)
	registerCodeCommands(recon)

	exploit := &cobra.Command{
		Use:   "exploit",
		Short: "offensive modules",
		RunE: func(*cobra.Command, []string) error {
			return usagef("the exploit tier is empty: aksum analyzes binaries read-only and never executes or modifies a target")
		},
	}
	report := &cobra.Command{
		Use:   "report",
		Short: "reporting modules",
		RunE: func(*cobra.Command, []string) error {
			return usagef("the report tier is empty: write a full report with 'aksum recon analyze <target> --report <path>'")
		},
	}
	root.AddCommand(recon, exploit, report)

	// Backward-compatible top-level aliases. The tier form is the supported
	// grammar, but every pre-tier invocation keeps working as a hidden
	// command so existing scripts and muscle memory are not broken. Cobra
	// does not suggest hidden commands, so help stays clean.
	root.AddCommand(
		hiddenAlias("analyze", newAnalyzeCmd()),
		hiddenAlias("binary", newBinaryCmd()),
		hiddenAlias("pe", newPECmd()),
		hiddenAlias("sections", newSectionsCmd()),
		hiddenAlias("segments", newSegmentsCmd()),
		hiddenAlias("symbols", newSymbolsCmd()),
		hiddenAlias("imports", newImportsCmd()),
		hiddenAlias("strings", newStringsCmd()),
		hiddenAlias("surface", newSurfaceCmd()),
		hiddenAlias("dynamic", newDynamicCmd()),
		hiddenAlias("functions", newFunctionsCmd()),
		hiddenAlias("disassemble", newDisassembleCmd()),
		hiddenAlias("calls", newCallsCmd()),
		hiddenAlias("cfg", newCfgCmd()),
		hiddenAlias("xrefs", newXrefsCmd()),
	)
	return root
}

// hiddenAlias registers a command under its bare name, hidden from help, so
// the pre-tier invocation form keeps resolving. The trailing usage breadcrumb
// (e.g. "dynamic <plan|run> <target>") is preserved.
func hiddenAlias(name string, cmd *cobra.Command) *cobra.Command {
	if old := cmd.Name(); name != old {
		cmd.Use = name + cmd.Use[len(old):]
	}
	cmd.Hidden = true
	return cmd
}

// ExecuteArgsContext runs the command tree with an explicit argument vector
// under a caller-supplied context and returns the process exit code.
//
// The interactive TUI drives this form: it runs commands in-process on its
// own goroutine and must be able to cancel one execution without tearing
// down the process, so the work follows a context the caller owns rather
// than process-wide signal handling. The tree is rebuilt per call, so no
// state survives from one execution to the next.
func ExecuteArgsContext(ctx context.Context, args []string) int {
	root := newRootCmd()
	root.SetContext(ctx)
	root.SetArgs(args)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err.Error())
		var ue usageError
		var use unsupportedError
		switch {
		case errors.As(err, &ue):
			return exitcode.Usage
		case errors.As(err, &use):
			return exitcode.Unsupported
		case errors.Is(err, context.Canceled):
			return exitcode.Interrupted
		default:
			return exitcode.Runtime
		}
	}
	return exitcode.Success
}
