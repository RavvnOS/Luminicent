package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewLoginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate the CLI with GitHub/Luminicent.",
		Long:  "Authenticate the CLI with GitHub/Luminicent.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "Luminicent login command")
			fmt.Fprintln(cmd.OutOrStdout(), "Login functionality is not implemented yet.")
		},
	}

	return cmd
}
