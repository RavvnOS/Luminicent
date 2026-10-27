package cmd

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:     "luminicent",
	Short:   "Luminicent security and production testing platform",
	Version: "0.1.0",
}

func Execute() error {
	return rootCmd.Execute()
}
