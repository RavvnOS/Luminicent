package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

type FindingsError struct {
	Count int
}

func (e FindingsError) Error() string {
	return fmt.Sprintf("scan completed with %d finding(s)", e.Count)
}

func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var findingsErr FindingsError
	if errors.As(err, &findingsErr) {
		return 2
	}
	return 1
}

var rootCmd = &cobra.Command{
	Use:           "luminicent",
	Short:         "Luminicent security and production testing platform",
	Version:       "0.1.0",
	SilenceErrors: true,
	SilenceUsage:  true,
}

func Execute() error {
	return rootCmd.Execute()
}

func ExecuteContext(ctx context.Context) error {
	return rootCmd.ExecuteContext(ctx)
}
