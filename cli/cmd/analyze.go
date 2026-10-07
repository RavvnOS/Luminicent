package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewAnalyzeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze an application for production readiness/security.",
		Long:  "Analyze an application for production readiness/security.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "Luminicent analyze command")
			fmt.Fprintln(cmd.OutOrStdout(), "Analyze functionality is not implemented yet.")
		},
	}

	return cmd
}
