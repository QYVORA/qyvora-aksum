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

var formatFlag string
var quietFlag bool
var eventsFlag string

// Execute runs the root command against os.Args and returns the exit code.
// The caller owns process termination.
func Execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return executeArgs(ctx, os.Args[1:])
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "aksum",
		Short: "Binary security assessment & reverse-engineering platform",
		Long: `aksum is a terminal-first binary-security assessment platform.

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
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if formatFlag != "" && formatFlag != "terminal" && formatFlag != "json" {
				return usagef("invalid --format %q (terminal, json)", formatFlag)
			}
			if eventsFlag != "" && eventsFlag != "stdout" && eventsFlag != "stderr" {
				// File paths are allowed too; validate creatable lazily per command.
				if eventsFlag[0] == '-' {
					return usagef("invalid --events value %q (stdout, stderr, or file path)", eventsFlag)
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return usagef("unknown command %q (try 'aksum --help')", args[0])
			}
			return cmd.Help()
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
	pf.StringVarP(&formatFlag, "format", "f", "", "output format: terminal, json")
	pf.BoolVarP(&quietFlag, "quiet", "q", false, "suppress non-error terminal output")
	pf.StringVar(&eventsFlag, "events", "", "emit JSONL event stream to stdout, stderr, or a file path")

	root.SetVersionTemplate(fmt.Sprintf("aksum %s\n", version.Version))
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageError{err}
	})

	root.AddCommand(newVersionCmd())
	registerTargetCommands(root)
	return root
}

func executeArgs(ctx context.Context, args []string) int {
	root := newRootCmd()
	root.SetContext(ctx)
	root.SetArgs(args)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err.Error())
		var ue usageError
		switch {
		case errors.As(err, &ue):
			return exitcode.Usage
		case errors.Is(err, context.Canceled):
			return exitcode.Interrupted
		default:
			return exitcode.Runtime
		}
	}
	return exitcode.Success
}
