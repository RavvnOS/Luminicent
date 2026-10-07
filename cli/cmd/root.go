package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "luminicent",
		Short: "Luminicent DevOps deployment CLI",
		Long: `Luminicent DevOps Deployment CLI

Luminicent is a DevOps deployment and application management CLI for managing
application deployments, environment status, logs, cleanup operations, and
production readiness checks for Linux-based workflows.`,
		Example: `  luminicent --help
  luminicent version
  luminicent deploy
  luminicent status`,
		SilenceErrors: true,
		SilenceUsage:  true,
		Version:       Version,
	}

	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)

	rootCmd.AddCommand(
		NewDeployCmd(),
		NewStatusCmd(),
		NewLogsCmd(),
		NewStopCmd(),
		NewCleanupCmd(),
		NewAnalyzeCmd(),
		NewLoginCmd(),
		NewConfigCmd(),
		NewVersionCmd(),
	)

	return rootCmd
}

func Execute() {
	if err := NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
