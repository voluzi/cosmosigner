package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/voluzi/cosmosigner/internal/backend"
	"github.com/voluzi/cosmosigner/internal/clusterid"
	"github.com/voluzi/cosmosigner/internal/config"
)

// NewClaimKeyCmd builds the one-shot administrative key-claim command.
func NewClaimKeyCmd() *cobra.Command {
	var clusterID string
	command := &cobra.Command{
		Use:   "claim-key",
		Short: "Bind an existing key resource to one Raft signing history",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if err := clusterid.Validate(clusterID); err != nil {
				return err
			}
			cfg, err := config.LoadBackend(func(c *backend.Config) { overlayBackendFlags(command, c) })
			if err != nil {
				return err
			}
			be, err := backend.New(cfg)
			if err != nil {
				return err
			}
			defer be.Close()

			if cfg.Type == backend.TypeGCPKMS {
				fmt.Fprintln(command.ErrOrStderr(), "WARNING: Cloud KMS label updates have no atomic compare-and-set; stop signers and externally serialize the initial claim")
			}
			if err := be.ClaimCluster(command.Context(), clusterID); err != nil {
				return err
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "claimed %s for cluster %s\n", backend.BindingResource(be), clusterID)
			return err
		},
	}
	command.Flags().StringVar(&clusterID, "cluster-id", "", "cluster ID printed by start --initialize-only")
	registerBackendFlags(command)
	return command
}
