package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var testCmd = &cobra.Command{
	Use:   "test <target>",
	Short: "Test a target project",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Target:", args[0])
		fmt.Println("Testing engine not implemented yet.")
	},
}

func init() {
	rootCmd.AddCommand(testCmd)
}
