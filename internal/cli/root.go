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

var formatFlag string
var quietFlag bool
var eventsFlag string

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

Run it with no arguments to enter an interactive console session
(contextual prompt, command history, tab completion), or use the
same commands one-shot: aksum analyze <target>, aksum strings ...

It identifies a binary, enumerates its structure (sections, segments,
symbols, imports), analyzes strings and code, discovers functions,
builds call/control-flow graphs, classifies security-relevant APIs,
maps attack surface, and reports candidate weaknesses as evidence-
backed findings with explicit confidence.

Authorized use only: analyze software you own or are authorized to
assess.`,
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
			// Machine-oriented global flags keep the classic behaviour: a
			// redirected stdout, a machine report, or a quiet run must not be
			// handed a full-screen interface.
			//
			// An event destination is deliberately not listed here. It used to
			// be, which meant `aksum --events out.jsonl` printed the help text
			// and said nothing about why. runTUI refuses that combination with
			// an explanation, and refusing a TTY run is safe there because the
			// interactive check below still sends redirected output to help.
			if formatFlag == "json" || quietFlag {
				return cmd.Help()
			}
			return runTUI(cmd.Root(), cmd.Context())
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
	// -o/--output is the flag the shared conformance layer drives every
	// framework with ("version -o json"). --format/-f is kept as an alias so
	// existing aksum callers and scripts keep working; both write the same
	// variable, so whichever appears last on the command line wins.
	pf.StringVarP(&formatFlag, "output", "o", "", "output format: terminal, json")
	pf.StringVarP(&formatFlag, "format", "f", "", "output format: terminal, json (alias for --output)")
	pf.BoolVarP(&quietFlag, "quiet", "q", false, "suppress non-error terminal output")
	pf.StringVar(&eventsFlag, "events", "", "emit JSONL event stream to stdout, stderr, or a file path")

	root.SetVersionTemplate(fmt.Sprintf("aksum %s\n", version.Version))
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageError{err}
	})

	root.AddCommand(commandTUI(),
		newVersionCmd(), newAnalyzeCmd(), newDynamicCmd(), newUpdatesCmd())
	registerTargetCommands(root)
	registerCodeCommands(root)
	return root
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
