package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/voluzi/cosmosigner/internal/version"
)

// NewVersionCmd builds the `version` command.
func NewVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Printf("cosmosigner %s (commit %s, built %s)\n", version.Version, version.Commit, version.Date)
			return nil
		},
	}
}
