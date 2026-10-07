package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show deployment status.",
		Long:  "Show deployment status.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "Luminicent status command")
			fmt.Fprintln(cmd.OutOrStdout(), "Status functionality is not implemented yet.")
		},
	}

	return cmd
}
