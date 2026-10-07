package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewLogsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Display or follow deployment logs.",
		Long:  "Display or follow deployment logs.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "Luminicent logs command")
			fmt.Fprintln(cmd.OutOrStdout(), "Logs functionality is not implemented yet.")
		},
	}

	return cmd
}
