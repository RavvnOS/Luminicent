package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/arvind-git04/Luminicent/cli/internal/acquisition"
	"github.com/arvind-git04/Luminicent/cli/internal/envconfig"
	"github.com/arvind-git04/Luminicent/cli/internal/scanner"
	"github.com/spf13/cobra"
)

type testCommandDependencies struct {
	detectTarget    func(string) acquisition.TargetType
	acquireLocal    func(string) (string, error)
	acquireGit      func(context.Context, string, string) (string, error)
	validateEnvFile func(string) error
	absPath         func(string) (string, error)
	stat            func(string) (os.FileInfo, error)
	removeAll       func(string) error
	backendURL      func() string
	scanProject     func(context.Context, string, scanner.Config) (scanner.Result, error)
}

func NewTestCmd() *cobra.Command {
	return newTestCmd(testCommandDependencies{
		detectTarget:    acquisition.DetectTarget,
		acquireLocal:    acquisition.AcquireLocalProject,
		acquireGit:      acquisition.AcquireGitProjectContext,
		validateEnvFile: envconfig.ValidateFile,
		absPath:         filepath.Abs,
		stat:            os.Stat,
		removeAll:       os.RemoveAll,
		backendURL:      func() string { return os.Getenv(scanner.BackendURLEnv) },
		scanProject: func(ctx context.Context, projectPath string, config scanner.Config) (scanner.Result, error) {
			return scanner.NewClient().Scan(ctx, projectPath, config)
		},
	})
}

func newTestCmd(deps testCommandDependencies) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test <target>",
		Short: "Test a target application.",
		Long:  "Test a target application. Requires LUMINICENT_BACKEND_URL and LUMINICENT_API_TOKEN.",
		Example: `  luminicent test ./sample project
  luminicent test git@github.com:user/repository.git --branch main
  luminicent test ./sample project --env-file ./project.env`,
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
			branchFlag := cmd.Flags().Lookup("branch")
			if branchFlag != nil && branchFlag.Changed {
				if err := validateBranch(branch); err != nil {
					return err
				}
				if deps.detectTarget(args[0]) != acquisition.GitTarget {
					return fmt.Errorf("--branch can only be used with a Git repository target")
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
	cmd.Flags().StringArray("env", nil, "Environment variable in KEY=VALUE format (validated, not sent to the backend).")
	cmd.Flags().String("env-file", "", "Environment file to validate and exclude from the uploaded project.")

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
		projectDir, err = deps.acquireGit(cmd.Context(), target, branch)
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

	var excludedPaths []string
	if envFile != "" {
		resolvedEnvFile, err := deps.absPath(envFile)
		if err != nil {
			return fmt.Errorf("resolve environment file path: %w", err)
		}
		if err := deps.validateEnvFile(resolvedEnvFile); err != nil {
			return fmt.Errorf("validate explicitly supplied environment file: %w", err)
		}
		excludedPaths = append(excludedPaths, resolvedEnvFile)
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
			excludedPaths = append(excludedPaths, discoveredEnvFile)
		}
	}

	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Test target type: %s\n", targetType); err != nil {
		return err
	}
	if branch != "" {
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Branch: %s\n", branch); err != nil {
			return err
		}
	}
	result, err := deps.scanProject(cmd.Context(), projectDir, scanner.Config{
		BackendURL:   deps.backendURL(),
		APIToken:     os.Getenv(scanner.APITokenEnv),
		ExcludePaths: excludedPaths,
	})
	if err != nil {
		return fmt.Errorf("scan project: %w", err)
	}
	outcome, err := scanner.AssessReport(result.Report)
	if err != nil {
		return fmt.Errorf("validate scanner report: %w", err)
	}

	displayReport, err := sanitizeReportPath(result.Report, outcome.Status)
	if err != nil {
		return fmt.Errorf("prepare scanner report for display: %w", err)
	}
	var formattedReport bytes.Buffer
	if err := json.Indent(&formattedReport, displayReport, "", "  "); err != nil {
		return fmt.Errorf("format scanner report: %w", err)
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Luminicent analysis report (scan %s):\n", outcome.Status); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(
		cmd.OutOrStdout(),
		"Findings detected: %t (%d)\n",
		outcome.FindingsDetected,
		outcome.FindingCount,
	); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout(), "Scope: Dockerfile/configuration, project structure, bounded hard-coded credential, TLS/HTTP, CORS/debug, and supported npm dependency checks; no complete OWASP assessment, dynamic vulnerability testing, or exploit verification."); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(
		cmd.OutOrStdout(),
		"Coverage: %d passed, %d with findings, %d failed, %d skipped, %d unsupported, %d incomplete\n",
		outcome.Coverage.Passed,
		outcome.Coverage.Findings,
		outcome.Coverage.Failed,
		outcome.Coverage.Skipped,
		outcome.Coverage.Unsupported,
		outcome.Coverage.Incomplete,
	); err != nil {
		return err
	}
	for _, check := range outcome.Checks {
		if _, err := fmt.Fprintf(
			cmd.OutOrStdout(),
			"Check %s (%s): %s. %s\n",
			check.Name,
			check.Status,
			check.Scope,
			check.Explanation,
		); err != nil {
			return err
		}
	}
	if outcome.Explanation != "" {
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Result note: %s\n", outcome.Explanation); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout(), formattedReport.String()); err != nil {
		return err
	}
	if outcome.FindingsDetected {
		return FindingsError{Count: outcome.FindingCount}
	}
	if outcome.Status == "partial" {
		if outcome.Explanation != "" {
			return fmt.Errorf("%s", outcome.Explanation)
		}
		return fmt.Errorf("scan completed with partial results; one or more checks failed")
	}
	return nil
}

func sanitizeReportPath(raw json.RawMessage, scanStatus string) (json.RawMessage, error) {
	var report map[string]json.RawMessage
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, err
	}
	if projectRaw, exists := report["project"]; exists {
		var project map[string]json.RawMessage
		if err := json.Unmarshal(projectRaw, &project); err != nil {
			return nil, err
		}
		if _, exists := project["path"]; exists {
			project["path"] = json.RawMessage(`"."`)
			sanitizedProject, err := json.Marshal(project)
			if err != nil {
				return nil, err
			}
			report["project"] = sanitizedProject
		}
	}
	if scanStatus == "partial" {
		if scanRaw, exists := report["scan"]; exists {
			var scan map[string]json.RawMessage
			if err := json.Unmarshal(scanRaw, &scan); err != nil {
				return nil, err
			}
			var status string
			if err := json.Unmarshal(scan["status"], &status); err != nil {
				return nil, err
			}
			if status == "completed" {
				scan["status"] = json.RawMessage(`"partial"`)
				normalizedScan, err := json.Marshal(scan)
				if err != nil {
					return nil, err
				}
				report["scan"] = normalizedScan
			}
		}
	}
	return json.Marshal(report)
}
