package cmd

import (
	"github.com/spf13/cobra"

	"github.com/voluzi/cosmosigner/internal/backend"
	"github.com/voluzi/cosmosigner/internal/config"
)

// NewPubkeyCmd builds the `pubkey` command.
func NewPubkeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pubkey",
		Short: "Print the consensus address and public key for a backend",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.LoadBackend(func(c *backend.Config) { overlayBackendFlags(cmd, c) })
			if err != nil {
				return err
			}
			b, err := backend.New(cfg)
			if err != nil {
				return err
			}
			defer b.Close()
			pub, err := b.PubKey()
			if err != nil {
				return err
			}
			printPubKey(pub.Address().String(), pub.Bytes())
			return nil
		},
	}
	registerBackendFlags(cmd)
	return cmd
}
