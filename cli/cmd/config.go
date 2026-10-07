package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage CLI configuration.",
		Long:  "Manage CLI configuration.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "Luminicent config command")
			fmt.Fprintln(cmd.OutOrStdout(), "Configuration functionality is not implemented yet.")
		},
	}

	return cmd
}
