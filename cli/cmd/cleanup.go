package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewCleanupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Remove deployment resources.",
		Long:  "Remove deployment resources.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "Luminicent cleanup command")
			fmt.Fprintln(cmd.OutOrStdout(), "Cleanup functionality is not implemented yet.")
		},
	}

	return cmd
}
