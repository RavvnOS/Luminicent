package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewStopCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop a running deployment.",
		Long:  "Stop a running deployment.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "Luminicent stop command")
			fmt.Fprintln(cmd.OutOrStdout(), "Stop functionality is not implemented yet.")
		},
	}

	return cmd
}
