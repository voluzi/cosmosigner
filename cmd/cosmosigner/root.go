// Command cosmosigner is a Vault/KMS-backed CometBFT remote signer with
// embedded-raft double-sign protection.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/voluzi/cosmosigner/cmd/cosmosigner/cmd"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "cosmosigner",
		Short:         "Vault/KMS-backed CometBFT remote signer with embedded-raft double-sign protection",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	// Config layering (defaults → file → env → flag) lives in the config
	// package; every flag has a matching COSMOSIGNER_* env var declared on the
	// config struct. --config and --log-level are global.
	root.PersistentFlags().String("config", "", "path to config file (yaml); or COSMOSIGNER_CONFIG")
	root.PersistentFlags().String("log-level", "info", "log level: debug, info, warn, error")

	root.AddCommand(
		cmd.NewStartCmd(),
		cmd.NewProvisionCmd(),
		cmd.NewImportCmd(),
		cmd.NewPubkeyCmd(),
		cmd.NewVersionCmd(),
	)
	return root
}
