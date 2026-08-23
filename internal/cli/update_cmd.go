// update_cmd implements `aksum updates`: check the running version against
// aksum's official QYVORA GitHub releases and install a newer release after
// cryptographic verification. See internal/selfupdate for the shared flow.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-aksum/internal/selfupdate"
	"github.com/QYVORA/qyvora-aksum/internal/updatecfg"
)

func newUpdatesCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "updates",
		Aliases: []string{"update"},
		Short:   "Update aksum from official QYVORA GitHub releases",
		Long: `Check for a newer aksum release and install it.

The installed version is compared against the latest official QYVORA
GitHub release for this platform. If an update exists, it is downloaded,
verified against the release SHA-256 manifest, and swapped in atomically;
the previous binary is never touched unless every step succeeds.

No Go toolchain, Git, or source checkout is required.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := selfupdate.Options{Out: cmd.OutOrStdout()}
			jsonMode := formatFlag == "json" || quietFlag
			if jsonMode {
				opts.Quiet = true
			}

			res, err := selfupdate.Run(cmd.Context(), updatecfg.Config(), opts)
			if jsonMode {
				payload := map[string]string{
					"framework": "aksum",
					"command":   "updates",
					"installed": res.Current,
					"latest":    res.Latest,
				}
				switch res.Status {
				case selfupdate.StatusUpdated:
					payload["status"] = "updated"
					payload["path"] = res.Path
				case selfupdate.StatusCurrent:
					payload["status"] = "current"
				case selfupdate.StatusNewerInstalled:
					payload["status"] = "newer_installed"
				}
				if err != nil {
					payload["status"] = "failed"
					payload["error"] = err.Error()
					var ue *selfupdate.UpdateError
					if errors.As(err, &ue) {
						payload["kind"] = string(ue.Kind)
					}
				}
				if jerr := json.NewEncoder(os.Stdout).Encode(payload); jerr != nil { //nolint:err113 // stable payload
					return jerr
				}
			}

			return enrichUpdateError(err)
		},
	}
}

// enrichUpdateError turns permission failures into actionable multi-line
// guidance while keeping every other failure a single clean line; raw causes
// never reach the terminal unless --verbose debugging is added upstream.
func enrichUpdateError(err error) error {
	if err == nil {
		return nil
	}
	var ue *selfupdate.UpdateError
	if !errors.As(err, &ue) {
		return err
	}
	if ue.Kind == selfupdate.KindPermission && ue.Path() != "" {
		return fmt.Errorf("%s\n\n%s", ue.Error(), selfupdate.PermissionHint("aksum", ue.Path()))
	}
	return ue
}
