package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/arvind-git04/Luminicent/cli/internal/acquisition"
	"github.com/arvind-git04/Luminicent/cli/internal/envconfig"
	"github.com/spf13/cobra"
)

type testCommandDependencies struct {
	detectTarget    func(string) acquisition.TargetType
	acquireLocal    func(string) (string, error)
	acquireGit      func(string) (string, error)
	validateEnvFile func(string) error
	absPath         func(string) (string, error)
	stat            func(string) (os.FileInfo, error)
	removeAll       func(string) error
}

func NewTestCmd() *cobra.Command {
	return newTestCmd(testCommandDependencies{
		detectTarget:    acquisition.DetectTarget,
		acquireLocal:    acquisition.AcquireLocalProject,
		acquireGit:      acquisition.AcquireGitProject,
		validateEnvFile: envconfig.ValidateFile,
		absPath:         filepath.Abs,
		stat:            os.Stat,
		removeAll:       os.RemoveAll,
	})
}

func newTestCmd(deps testCommandDependencies) *cobra.Command {
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
			branch, err := cmd.Flags().GetString("branch")
			if err != nil {
				return err
			}
			envFile, err := cmd.Flags().GetString("env-file")
			if err != nil {
				return err
			}
			return runTestCommand(cmd, args[0], branch, envFile, deps)
		},
	}

	cmd.Flags().String("branch", "", "Git branch to test when the target is a Git SSH repository.")
	cmd.Flags().StringArray("env", nil, "Environment variable in KEY=VALUE format.")
	cmd.Flags().String("env-file", "", "Path to an environment file.")

	return cmd
}

func runTestCommand(
	cmd *cobra.Command,
	target string,
	branch string,
	envFile string,
	deps testCommandDependencies,
) (resultErr error) {
	targetType := deps.detectTarget(target)

	var projectDir string
	switch targetType {
	case acquisition.LocalTarget:
		var err error
		projectDir, err = deps.acquireLocal(target)
		if err != nil {
			return fmt.Errorf("acquire local project: %w", err)
		}
	case acquisition.GitTarget:
		var err error
		projectDir, err = deps.acquireGit(target)
		if err != nil {
			return fmt.Errorf("acquire Git project: %w", err)
		}
		defer func() {
			if err := deps.removeAll(projectDir); err != nil {
				cleanupErr := fmt.Errorf("clean up temporary Git project: %w", err)
				if resultErr != nil {
					resultErr = errors.Join(resultErr, cleanupErr)
				} else {
					resultErr = cleanupErr
				}
			}
		}()
	default:
		return fmt.Errorf("unsupported target type %q", targetType)
	}

	if envFile != "" {
		resolvedEnvFile, err := deps.absPath(envFile)
		if err != nil {
			return fmt.Errorf("resolve environment file path: %w", err)
		}
		if err := deps.validateEnvFile(resolvedEnvFile); err != nil {
			return fmt.Errorf("validate explicitly supplied environment file: %w", err)
		}
	} else if targetType == acquisition.LocalTarget {
		discoveredEnvFile := filepath.Join(projectDir, ".env")
		_, err := deps.stat(discoveredEnvFile)
		switch {
		case errors.Is(err, os.ErrNotExist):
			// A local project may omit .env.
		case err != nil:
			return fmt.Errorf("check local project environment file: %w", err)
		default:
			if err := deps.validateEnvFile(discoveredEnvFile); err != nil {
				return fmt.Errorf("validate local project environment file: %w", err)
			}
		}
	}

	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Test target: %s\n", target); err != nil {
		return err
	}
	if branch != "" {
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Branch: %s\n", branch); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(cmd.OutOrStdout(), "Testing functionality is not implemented yet.")
	return err
}
