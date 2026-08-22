package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-aksum/internal/dynamic"
)

func newDynamicCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dynamic <plan|run> <target>",
		Short: "Dynamic-analysis planning and execution architecture",
		Long: `Builds auditable execution plans under a mechanical safety
policy (timeout, no network by default, output caps, explicit consent).

This build bundles NO sandbox backend: 'dynamic plan' validates and
prints what WOULD run, and 'dynamic run' refuses with exit code 3.
Nothing in aksum executes a target it cannot honestly contain.`,
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) == 0 {
				return usagef("dynamic requires a subcommand: plan or run")
			}
			switch args[0] {
			case "plan":
				return runDynamicPlan(c, args[1:])
			case "run":
				return runDynamicRun(c, args[1:])
			default:
				return usagef("unknown dynamic subcommand %q (plan, run)", args[0])
			}
		},
	}
	cmd.Flags().Duration("timeout", 5*time.Second, "wall-clock cap per proposed run")
	cmd.Flags().Bool("allow-network", false, "allow network egress in the proposed policy")
	cmd.Flags().Bool("allow-file-write", false, "allow filesystem writes outside scratch space")
	cmd.Flags().Int("max-output-bytes", 1<<20, "captured output cap in bytes")
	cmd.Flags().Bool("yes", false, "explicitly confirm execution risk (required)")
	cmd.Flags().StringSlice("arg", nil, "argument to record in the plan (repeatable)")
	return cmd
}

func dynamicPolicyFromFlags(cmd *cobra.Command) (dynamic.Policy, error) {
	pol := dynamic.Defaults()
	var err error
	if pol.Timeout, err = cmd.Flags().GetDuration("timeout"); err != nil {
		return pol, err
	}
	if pol.AllowNetwork, err = cmd.Flags().GetBool("allow-network"); err != nil {
		return pol, err
	}
	if pol.AllowFileWrite, err = cmd.Flags().GetBool("allow-file-write"); err != nil {
		return pol, err
	}
	if pol.MaxOutputBytes, err = cmd.Flags().GetInt("max-output-bytes"); err != nil {
		return pol, err
	}
	if pol.ConsentConfirmed, err = cmd.Flags().GetBool("yes"); err != nil {
		return pol, err
	}
	return pol, nil
}

func runDynamicPlan(c *cobra.Command, args []string) error {
	path, err := oneArg(c, args)
	if err != nil {
		return err
	}
	t, err := loadTarget(path)
	if err != nil {
		return err
	}
	rawArgs, aerr := c.Flags().GetStringSlice("arg")
	if aerr != nil {
		return usagef("%v", aerr)
	}
	pol, err := dynamicPolicyFromFlags(c)
	if err != nil {
		return usagef("%v", err)
	}
	plan, perr := dynamic.BuildPlan(t, rawArgs, pol)
	if perr != nil {
		return usagef("%v", perr)
	}

	p := newPrinter()
	if p.Format() == "json" {
		return json.NewEncoder(os.Stdout).Encode(plan)
	}
	data, merr := json.MarshalIndent(plan, "", "  ")
	if merr != nil {
		return merr
	}
	fmt.Println(string(data))
	p.Warn("DYNAMIC", "plan validated; this build performs no execution — feed the plan to an external sandbox backend of your own")
	return nil
}

func runDynamicRun(_ *cobra.Command, args []string) error {
	if len(args) == 0 {
		return usagef("dynamic run requires <target>")
	}
	return unsupportedf("no dynamic-execution backend is bundled with this build: " +
		"aksum refuses to execute binaries without a real isolation boundary; " +
		"use 'aksum dynamic plan' to produce a validated plan for your own sandbox")
}
