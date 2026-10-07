package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewDeployCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Deploy an application.",
		Long:  "Deploy an application.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "Luminicent deploy command")
			fmt.Fprintln(cmd.OutOrStdout(), "Deployment functionality is not implemented yet.")
		},
	}

	return cmd
}
