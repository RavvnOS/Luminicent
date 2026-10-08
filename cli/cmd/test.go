package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewTestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test <target>",
		Short: "Test a target application.",
		Long:  "Test a target application.",
		Example: `  luminicent test ./sample project
  luminicent test git@github.com:user/repository.git --branch main
  luminicent test ./sample project --env PORT=8080 --env NODE_ENV=production`,
		Args: cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			envValues, err := cmd.Flags().GetStringArray("env")
			if err != nil {
				return err
			}
			if err := validateKeyValueList(envValues, "--env"); err != nil {
				return err
			}

			branch, err := cmd.Flags().GetString("branch")
			if err != nil {
				return err
			}
			if branch != "" {
				if err := validateBranch(branch); err != nil {
					return err
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			envValues, _ := cmd.Flags().GetStringArray("env")
			branch, _ := cmd.Flags().GetString("branch")
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "Test target: %s\n", args[0])
			if err != nil {
				return err
			}
			if branch != "" {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Branch: %s\n", branch)
				if err != nil {
					return err
				}
			}
			if len(envValues) > 0 {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Environment: %v\n", envValues)
				if err != nil {
					return err
				}
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "Testing functionality is not implemented yet.")
			return err
		},
	}

	cmd.Flags().String("branch", "", "Git branch to test when the target is a Git SSH repository.")
	cmd.Flags().StringArray("env", nil, "Environment variable in KEY=VALUE format.")

	return cmd
}
