package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var Version = "dev"

func NewVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Display CLI version.",
		Long:  "Display CLI version.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "Luminicent CLI\nVersion: %s\n", Version)
		},
	}

	return cmd
}
