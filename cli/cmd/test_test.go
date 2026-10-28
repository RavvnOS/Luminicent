package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arvind-git04/Luminicent/cli/internal/acquisition"
	"github.com/arvind-git04/Luminicent/cli/internal/scanner"
)

func TestTestCommandEnvFileFlag(t *testing.T) {
	t.Run("flag is registered with empty default", func(t *testing.T) {
		cmd := NewTestCmd()
		flag := cmd.Flags().Lookup("env-file")
		if flag == nil {
			t.Fatal("--env-file flag is not registered")
		}
		if flag.DefValue != "" {
			t.Errorf("--env-file default = %q, want empty", flag.DefValue)
		}
	})

	t.Run("flag accepts path", func(t *testing.T) {
		cmd := newTestCmd(defaultTestCommandDependencies())
		projectDir := t.TempDir()
		envFile := filepath.Join(t.TempDir(), "project.env")
		if err := os.WriteFile(envFile, []byte("KEY=value\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(&output)
		cmd.SetArgs([]string{projectDir, "--env-file", envFile})
		if err := cmd.Execute(); ExitCode(err) != 1 {
			t.Fatalf("execute with --env-file error = %v, want partial-coverage exit code 1", err)
		}
		gotEnvFile, err := cmd.Flags().GetString("env-file")
		if err != nil {
			t.Fatalf("get --env-file: %v", err)
		}
		if gotEnvFile != envFile {
			t.Errorf("--env-file = %q, want %q", gotEnvFile, envFile)
		}
		if !strings.Contains(output.String(), "Test target type: local\n") {
			t.Errorf("command output does not report target type: %q", output.String())
		}
		if strings.Contains(output.String(), projectDir) {
			t.Errorf("command output exposed the local project path: %q", output.String())
		}
	})

	t.Run("flag is optional", func(t *testing.T) {
		cmd := newTestCmd(defaultTestCommandDependencies())
		projectDir := t.TempDir()
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(&output)
		cmd.SetArgs([]string{projectDir})

		if err := cmd.Execute(); ExitCode(err) != 1 {
			t.Fatalf("execute without --env-file error = %v, want partial-coverage exit code 1", err)
		}
		if !strings.Contains(output.String(), "Test target type: local\n") {
			t.Errorf("command output does not report target type: %q", output.String())
		}
	})
}

func defaultTestCommandDependencies() testCommandDependencies {
	return testCommandDependencies{
		detectTarget: acquisition.DetectTarget,
		acquireLocal: func(target string) (string, error) {
			return target, nil
		},
		acquireGit: func(context.Context, string, string) (string, error) {
			return "", errors.New("unexpected Git acquisition")
		},
		validateEnvFile: func(string) error { return nil },
		absPath:         filepath.Abs,
		stat:            os.Stat,
		removeAll:       os.RemoveAll,
		backendURL:      func() string { return "http://backend.test" },
		scanProject: func(context.Context, string, scanner.Config) (scanner.Result, error) {
			return scanner.Result{Report: withFullCheckList(validCommandReport())}, nil
		},
	}
}

func validCommandReport() json.RawMessage {
	return json.RawMessage(`{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0,"unknown":0},"dependencyAnalysis":{"source":"OSV","status":"completed","packageCount":0,"queriedPackageCount":0,"advisoryCount":0},"scan":{"status":"partial","findingsDetected":false,"findingCount":0,"checks":[{"id":"dockerfile_presence","status":"passed"},{"id":"dockerfile_configuration","status":"passed"},{"id":"dockerignore_configuration","status":"passed"},{"id":"environment_configuration","status":"passed"},{"id":"image_metadata","status":"passed"},{"id":"runtime_inspection","status":"passed"},{"id":"secret_pattern_search","status":"passed"},{"id":"insecure_transport_configuration","status":"passed"},{"id":"dangerous_application_configuration","status":"passed"},{"id":"project_structure","status":"passed"},{"id":"owasp_top_10","status":"unsupported"},{"id":"dynamic_vulnerability_testing","status":"unsupported"},{"id":"dependency_vulnerability_analysis","status":"passed"},{"id":"exploit_verification","status":"unsupported"}]}}`)
}

func withFullCheckList(raw json.RawMessage) json.RawMessage {
	var report map[string]json.RawMessage
	if json.Unmarshal(raw, &report) != nil {
		return raw
	}
	var scan map[string]json.RawMessage
	if json.Unmarshal(report["scan"], &scan) != nil || scan == nil {
		return raw
	}
	var checks []map[string]any
	if json.Unmarshal(scan["checks"], &checks) != nil {
		return raw
	}
	seen := make(map[string]bool)
	for _, check := range checks {
		id, _ := check["id"].(string)
		seen[id] = true
	}
	expected := []map[string]any{
		{"id": "dockerfile_presence", "status": "completed"},
		{"id": "dockerfile_configuration", "status": "completed"},
		{"id": "dockerignore_configuration", "status": "completed"},
		{"id": "environment_configuration", "status": "completed"},
		{"id": "image_metadata", "status": "completed"},
		{"id": "runtime_inspection", "status": "completed"},
		{"id": "secret_pattern_search", "status": "completed"},
		{"id": "insecure_transport_configuration", "status": "completed"},
		{"id": "dangerous_application_configuration", "status": "completed"},
		{"id": "project_structure", "status": "completed"},
		{"id": "owasp_top_10", "status": "unsupported"},
		{"id": "dynamic_vulnerability_testing", "status": "unsupported"},
		{"id": "dependency_vulnerability_analysis", "status": "completed"},
		{"id": "exploit_verification", "status": "unsupported"},
	}
	for _, check := range expected {
		id := check["id"].(string)
		if !seen[id] {
			checks = append(checks, check)
		}
	}
	for _, check := range checks {
		id, _ := check["id"].(string)
		status, _ := check["status"].(string)
		if check["name"] == nil {
			check["name"] = strings.ReplaceAll(id, "_", " ")
		}
		if check["scope"] == nil {
			check["scope"] = "Documented analyzer scope for " + strings.ReplaceAll(id, "_", " ") + "."
		}
		if check["explanation"] == nil {
			switch status {
			case "unsupported":
				check["explanation"] = "This check is not implemented."
			case "failed":
				check["explanation"] = "The check could not complete."
			case "not_performed", "skipped":
				check["explanation"] = "The check was intentionally skipped."
			case "incomplete":
				check["explanation"] = "The check could not assess its full scope."
			default:
				check["explanation"] = "No issues found within the stated scope."
			}
		}
	}
	scan["checks"], _ = json.Marshal(checks)
	for _, check := range checks {
		if check["id"] == "dependency_vulnerability_analysis" &&
			check["status"] == "completed" && len(report["dependencyAnalysis"]) == 0 {
			report["dependencyAnalysis"], _ = json.Marshal(map[string]any{
				"source": "OSV", "status": "completed", "packageCount": 0,
				"queriedPackageCount": 0, "advisoryCount": 0,
			})
		}
	}
	partial := false
	for _, check := range checks {
		switch check["status"] {
		case "failed", "unsupported", "not_performed", "skipped", "incomplete":
			partial = true
		}
	}
	if partial {
		scan["status"], _ = json.Marshal("partial")
	}
	report["scan"], _ = json.Marshal(scan)
	updated, err := json.Marshal(report)
	if err != nil {
		return raw
	}
	return updated
}

func executeTestCommand(t *testing.T, deps testCommandDependencies, args ...string) error {
	t.Helper()
	cmd := newTestCmd(deps)
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs(args)
	return cmd.Execute()
}

func TestTestCommandAcquiresLocalProjectAndDiscoversEnv(t *testing.T) {
	projectDir := t.TempDir()
	envPath := filepath.Join(projectDir, ".env")
	if err := os.WriteFile(envPath, []byte("KEY=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	deps := defaultTestCommandDependencies()
	localCalled := false
	validatedPath := ""
	deps.acquireLocal = func(target string) (string, error) {
		localCalled = true
		if target != "./local-project" {
			t.Errorf("local acquisition target = %q, want relative target", target)
		}
		return projectDir, nil
	}
	deps.validateEnvFile = func(path string) error {
		validatedPath = path
		return nil
	}

	if err := executeTestCommand(t, deps, "./local-project"); ExitCode(err) != 1 {
		t.Fatalf("execute test command error = %v, want partial-coverage exit code 1", err)
	}
	if !localCalled {
		t.Fatal("local acquisition was not called")
	}
	if validatedPath != envPath {
		t.Errorf("validated environment path = %q, want %q", validatedPath, envPath)
	}
}

func TestTestCommandPassesSelectedBranchToGitAcquisition(t *testing.T) {
	const branch = "release/phase-3"
	deps := defaultTestCommandDependencies()
	deps.acquireGit = func(_ context.Context, target, selectedBranch string) (string, error) {
		if target != "git@github.com:user/project.git" {
			t.Errorf("Git target = %q", target)
		}
		if selectedBranch != branch {
			t.Errorf("selected branch = %q, want %q", selectedBranch, branch)
		}
		return t.TempDir(), nil
	}
	deps.removeAll = func(string) error { return nil }
	var output bytes.Buffer
	cmd := newTestCmd(deps)
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"git@github.com:user/project.git", "--branch", branch})

	if err := cmd.Execute(); ExitCode(err) != 1 {
		t.Fatalf("execute with selected branch error = %v, want partial-coverage exit code 1", err)
	}
	if !strings.Contains(output.String(), "Branch: "+branch) {
		t.Errorf("output does not identify selected branch: %q", output.String())
	}
	if !strings.Contains(output.String(), "unsupported") ||
		!strings.Contains(output.String(), "no complete OWASP assessment, dynamic vulnerability testing, or exploit verification") {
		t.Errorf("output does not disclose incomplete coverage: %q", output.String())
	}
}

func TestTestCommandPassesCancellationContextToGitAcquisition(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	deps := defaultTestCommandDependencies()
	deps.acquireGit = func(gotContext context.Context, _, _ string) (string, error) {
		if !errors.Is(gotContext.Err(), context.Canceled) {
			t.Errorf("Git acquisition context error = %v, want cancellation", gotContext.Err())
		}
		return "", gotContext.Err()
	}
	cmd := newTestCmd(deps)
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"git@github.com:user/project.git", "--branch", "main"})

	err := cmd.Execute()
	if !errors.Is(err, context.Canceled) {
		t.Errorf("command error = %v, want context cancellation", err)
	}
}

func TestTestCommandRejectsInvalidBranchInput(t *testing.T) {
	tests := []struct {
		name   string
		target string
		branch string
	}{
		{"empty branch", "git@github.com:user/project.git", ""},
		{"malformed branch", "git@github.com:user/project.git", "release..bad"},
		{"branch on local target", "./project", "main"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			deps := defaultTestCommandDependencies()
			deps.acquireGit = func(context.Context, string, string) (string, error) {
				t.Fatal("Git acquisition must not run for invalid branch input")
				return "", nil
			}
			deps.acquireLocal = func(string) (string, error) {
				t.Fatal("local acquisition must not run when --branch is invalid")
				return "", nil
			}
			err := executeTestCommand(t, deps, testCase.target, "--branch", testCase.branch)
			if err == nil {
				t.Fatal("command succeeded with invalid branch input")
			}
			switch testCase.name {
			case "branch on local target":
				if !strings.Contains(err.Error(), "only be used with a Git repository") {
					t.Errorf("error = %v, want local target rejection", err)
				}
			default:
				if !strings.Contains(err.Error(), "--branch") {
					t.Errorf("error = %v, want clear branch validation context", err)
				}
			}
		})
	}
}

func TestTestCommandExplicitEnvFile(t *testing.T) {
	t.Setenv(scanner.APITokenEnv, "test-api-token")
	projectDir := t.TempDir()
	explicitEnvFile := filepath.Join(projectDir, "local-settings.txt")
	if err := os.WriteFile(explicitEnvFile, []byte("KEY=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	deps := defaultTestCommandDependencies()
	var validatedPath string
	var scannedPath string
	var scannedConfig scanner.Config
	deps.acquireLocal = func(string) (string, error) { return projectDir, nil }
	deps.validateEnvFile = func(path string) error {
		validatedPath = path
		return nil
	}
	deps.scanProject = func(_ context.Context, path string, config scanner.Config) (scanner.Result, error) {
		scannedPath = path
		scannedConfig = config
		return scanner.Result{Report: withFullCheckList(validCommandReport())}, nil
	}
	deps.stat = func(string) (os.FileInfo, error) {
		t.Fatal("automatic .env discovery must not run when --env-file is explicit")
		return nil, nil
	}

	if err := executeTestCommand(t, deps, "./local-project", "--env-file", explicitEnvFile); ExitCode(err) != 1 {
		t.Fatalf("execute with explicit env file error = %v, want partial-coverage exit code 1", err)
	}
	wantPath := explicitEnvFile
	if validatedPath != wantPath {
		t.Errorf("validated environment path = %q, want absolute path %q", validatedPath, wantPath)
	}
	if scannedPath != projectDir {
		t.Errorf("scanner project path = %q, want %q", scannedPath, projectDir)
	}
	if len(scannedConfig.ExcludePaths) != 1 || scannedConfig.ExcludePaths[0] != explicitEnvFile {
		t.Errorf("scanner exclusions = %q, want explicit env file %q", scannedConfig.ExcludePaths, explicitEnvFile)
	}
	if scannedConfig.APIToken != "test-api-token" {
		t.Errorf("scanner API token was not loaded from the environment")
	}
}

func TestTestCommandRejectsInvalidExplicitEnvFile(t *testing.T) {
	projectDir := t.TempDir()
	validationErr := errors.New("malformed environment file at line 3")
	deps := defaultTestCommandDependencies()
	deps.acquireLocal = func(string) (string, error) { return projectDir, nil }
	deps.validateEnvFile = func(string) error { return validationErr }
	deps.stat = func(string) (os.FileInfo, error) {
		t.Fatal("automatic discovery must not run after explicit validation fails")
		return nil, nil
	}

	err := executeTestCommand(t, deps, "./local-project", "--env-file", "invalid.env")
	if err == nil {
		t.Fatal("execute with invalid explicit env file error = nil, want error")
	}
	if !errors.Is(err, validationErr) {
		t.Errorf("execute error = %v, want wrapped validation error", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Errorf("execute error unexpectedly includes a secret: %v", err)
	}
}

func TestTestCommandMissingLocalEnvContinues(t *testing.T) {
	projectDir := t.TempDir()
	deps := defaultTestCommandDependencies()
	validated := false
	deps.acquireLocal = func(string) (string, error) { return projectDir, nil }
	deps.stat = func(path string) (os.FileInfo, error) {
		if path != filepath.Join(projectDir, ".env") {
			t.Errorf("stat path = %q, want local .env", path)
		}
		return nil, os.ErrNotExist
	}
	deps.validateEnvFile = func(string) error {
		validated = true
		return nil
	}

	if err := executeTestCommand(t, deps, "./local-project"); ExitCode(err) != 1 {
		t.Fatalf("execute without local .env error = %v, want partial-coverage exit code 1", err)
	}
	if validated {
		t.Error("environment validator called when .env was missing")
	}
}

func TestTestCommandGitAcquisitionAndCleanup(t *testing.T) {
	cloneDir := t.TempDir()
	deps := defaultTestCommandDependencies()
	gitCalled := false
	cleanupCalled := false
	deps.acquireGit = func(_ context.Context, target, branch string) (string, error) {
		gitCalled = true
		if target != "git@github.com:user/project.git" {
			t.Errorf("Git acquisition target = %q, want SSH URL", target)
		}
		if branch != "" {
			t.Errorf("Git acquisition branch = %q, want empty", branch)
		}
		return cloneDir, nil
	}
	deps.stat = func(string) (os.FileInfo, error) {
		t.Fatal("Git target should not trigger automatic .env discovery")
		return nil, nil
	}
	deps.removeAll = func(path string) error {
		cleanupCalled = true
		if path != cloneDir {
			t.Errorf("cleanup path = %q, want acquired clone %q", path, cloneDir)
		}
		return nil
	}

	if err := executeTestCommand(t, deps, "git@github.com:user/project.git"); ExitCode(err) != 1 {
		t.Fatalf("execute Git target error = %v, want partial-coverage exit code 1", err)
	}
	if !gitCalled {
		t.Fatal("Git acquisition was not called")
	}
	if !cleanupCalled {
		t.Fatal("temporary Git checkout was not cleaned up")
	}
}

func TestTestCommandAcquisitionErrors(t *testing.T) {
	t.Run("local", func(t *testing.T) {
		acquisitionErr := errors.New("directory is unreadable")
		deps := defaultTestCommandDependencies()
		deps.acquireLocal = func(string) (string, error) { return "", acquisitionErr }
		err := executeTestCommand(t, deps, "./local-project")
		if !errors.Is(err, acquisitionErr) {
			t.Errorf("execute error = %v, want wrapped acquisition error", err)
		}
	})

	t.Run("Git", func(t *testing.T) {
		acquisitionErr := errors.New("clone failed without repository details")
		deps := defaultTestCommandDependencies()
		deps.acquireGit = func(context.Context, string, string) (string, error) { return "", acquisitionErr }
		err := executeTestCommand(t, deps, "git@github.com:user/project.git")
		if !errors.Is(err, acquisitionErr) {
			t.Errorf("execute error = %v, want wrapped acquisition error", err)
		}
	})
}

func TestTestCommandGitCheckoutCleanedAfterValidationError(t *testing.T) {
	cloneDir := t.TempDir()
	validationErr := errors.New("invalid environment file")
	cleanupCalled := false
	deps := defaultTestCommandDependencies()
	deps.acquireGit = func(context.Context, string, string) (string, error) { return cloneDir, nil }
	deps.validateEnvFile = func(string) error { return validationErr }
	deps.removeAll = func(path string) error {
		cleanupCalled = true
		if path != cloneDir {
			t.Errorf("cleanup path = %q, want %q", path, cloneDir)
		}
		return nil
	}

	err := executeTestCommand(t, deps, "git@github.com:user/project.git", "--env-file", "project.env")
	if !errors.Is(err, validationErr) {
		t.Errorf("execute error = %v, want wrapped validation error", err)
	}
	if !cleanupCalled {
		t.Fatal("temporary Git checkout was not cleaned after validation failure")
	}
}

func TestTestCommandPropagatesScannerErrorAndCleansGitCheckout(t *testing.T) {
	cloneDir := t.TempDir()
	scanErr := errors.New("backend unavailable")
	cleanupCalled := false
	deps := defaultTestCommandDependencies()
	deps.acquireGit = func(context.Context, string, string) (string, error) { return cloneDir, nil }
	deps.scanProject = func(context.Context, string, scanner.Config) (scanner.Result, error) {
		return scanner.Result{}, scanErr
	}
	deps.removeAll = func(path string) error {
		cleanupCalled = true
		if path != cloneDir {
			t.Errorf("cleanup path = %q, want %q", path, cloneDir)
		}
		return nil
	}

	err := executeTestCommand(t, deps, "git@github.com:user/project.git")
	if !errors.Is(err, scanErr) {
		t.Errorf("execute error = %v, want wrapped scanner error", err)
	}
	if !cleanupCalled {
		t.Fatal("temporary Git checkout was not cleaned after scanner failure")
	}
}

func TestTestCommandPrintsPartialBackendReportAndCoverage(t *testing.T) {
	deps := defaultTestCommandDependencies()
	var output bytes.Buffer
	cmd := newTestCmd(deps)
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"./project"})

	if err := cmd.Execute(); ExitCode(err) != 1 {
		t.Fatalf("execute test command error = %v, want partial-coverage exit code 1", err)
	}
	if !strings.Contains(output.String(), "Luminicent analysis report (scan partial)") ||
		!strings.Contains(output.String(), "Findings detected: false (0)") ||
		!strings.Contains(output.String(), "no complete OWASP assessment, dynamic vulnerability testing, or exploit verification") ||
		!strings.Contains(output.String(), "unsupported") ||
		!strings.Contains(output.String(), "Coverage:") ||
		!strings.Contains(output.String(), "not implemented") ||
		!strings.Contains(output.String(), `"score": 100`) ||
		!strings.Contains(output.String(), `"status": "Excellent"`) {
		t.Errorf("CLI output does not contain backend report: %q", output.String())
	}
}

func TestTestCommandOutcomeAndExitCode(t *testing.T) {
	tests := []struct {
		name       string
		report     json.RawMessage
		wantExit   int
		wantOutput string
		wantError  string
	}{
		{
			name:       "finding-free scan with unsupported coverage",
			report:     validCommandReport(),
			wantExit:   1,
			wantOutput: "Findings detected: false (0)",
		},
		{
			name:       "findings with partial coverage",
			report:     json.RawMessage(`{"score":80,"status":"Good","issues":[{"severity":"High","title":"Risk indicator"}],"summary":{"critical":0,"high":1,"medium":0,"low":0},"scan":{"status":"completed","findingsDetected":true,"findingCount":1,"checks":[{"id":"secret_pattern_search","status":"completed"}]}}`),
			wantExit:   2,
			wantOutput: "Findings detected: true (1)",
		},
		{
			name:       "static finding details are displayed",
			report:     json.RawMessage(`{"score":80,"status":"Good","issues":[{"severity":"High","title":"Permissive wildcard CORS configured","description":"A CORS setting allows every origin.","recommendation":"Restrict origins.","checkId":"dangerous_application_configuration","ruleId":"LUM-CFG-001","file":"config/settings.json","line":42,"evidence":"CORS allowed origin=*"}],"summary":{"critical":0,"high":1,"medium":0,"low":0},"scan":{"status":"partial","findingsDetected":true,"findingCount":1,"checks":[{"id":"dangerous_application_configuration","status":"completed","findingCount":1}]}}`),
			wantExit:   2,
			wantOutput: "LUM-CFG-001",
		},
		{
			name:       "dependency advisory finding",
			report:     json.RawMessage(`{"score":90,"status":"Excellent","issues":[{"severity":"High","title":"Dependency vulnerability: library-a (GHSA-test-1234)","dependency":{"ecosystem":"npm","package":"library-a","installedVersion":"1.2.3","relationship":"direct","advisoryId":"GHSA-test-1234","fixedVersion":"2.0.0","advisoryModified":"2025-01-02T03:04:05Z"}}],"summary":{"critical":0,"high":1,"medium":0,"low":0},"dependencyAnalysis":{"source":"OSV","status":"completed","packageCount":1,"queriedPackageCount":1,"advisoryCount":1},"scan":{"status":"completed","findingsDetected":true,"findingCount":1,"checks":[{"id":"dependency_vulnerability_analysis","status":"completed"}]}}`),
			wantExit:   2,
			wantOutput: "Findings detected: true (1)",
		},
		{
			name:       "partial scan",
			report:     json.RawMessage(`{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"partial","findingsDetected":false,"findingCount":0,"checks":[{"id":"image_metadata","status":"failed"}]}}`),
			wantExit:   1,
			wantOutput: "scan partial",
		},
		{
			name:       "incomplete dependency coverage",
			report:     json.RawMessage(`{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"dependencyAnalysis":{"source":"OSV","status":"partial","reason":"unsupported_dependency_formats"},"scan":{"status":"partial","findingsDetected":false,"findingCount":0,"checks":[{"id":"dependency_vulnerability_analysis","status":"failed"}]}}`),
			wantExit:   1,
			wantOutput: "scan partial",
		},
		{
			name:       "unsupported dependency analysis",
			report:     json.RawMessage(`{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"completed","findingsDetected":false,"findingCount":0,"checks":[{"id":"dependency_vulnerability_analysis","status":"unsupported"}]}}`),
			wantExit:   1,
			wantOutput: "This check is not implemented.",
			wantError:  "one or more checks are failed, skipped, unsupported, or incomplete",
		},
		{
			name:       "legacy report without findings is indeterminate",
			report:     json.RawMessage(`{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0}}`),
			wantExit:   1,
			wantOutput: "scan partial",
			wantError:  "legacy report does not include executed check metadata; scan result is indeterminate",
		},
		{
			name:     "malformed report",
			report:   json.RawMessage(`{"score":100}`),
			wantExit: 1,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			deps := defaultTestCommandDependencies()
			deps.scanProject = func(context.Context, string, scanner.Config) (scanner.Result, error) {
				return scanner.Result{Report: withFullCheckList(testCase.report)}, nil
			}
			cmd := newTestCmd(deps)
			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&output)
			cmd.SetArgs([]string{"./private-local-project"})
			err := cmd.Execute()
			if got := ExitCode(err); got != testCase.wantExit {
				t.Fatalf("exit code = %d, want %d (error %v)", got, testCase.wantExit, err)
			}
			if testCase.wantError != "" && (err == nil || !strings.Contains(err.Error(), testCase.wantError)) {
				t.Errorf("command error = %v, want %q", err, testCase.wantError)
			}
			if testCase.wantOutput != "" && !strings.Contains(output.String(), testCase.wantOutput) {
				t.Errorf("output does not contain %q: %q", testCase.wantOutput, output.String())
			}
			if testCase.name == "findings with partial coverage" &&
				!strings.Contains(output.String(), "Luminicent analysis report (scan partial)") {
				t.Errorf("findings with incomplete coverage were not labeled partial: %q", output.String())
			}
			if testCase.name == "static finding details are displayed" &&
				(!strings.Contains(output.String(), `"file": "config/settings.json"`) ||
					!strings.Contains(output.String(), `"line": 42`) ||
					!strings.Contains(output.String(), `"evidence": "CORS allowed origin=*"`)) {
				t.Errorf("static finding location and evidence were not displayed: %q", output.String())
			}
			if testCase.name == "unsupported dependency analysis" &&
				!strings.Contains(output.String(), `"status": "partial"`) {
				t.Errorf("displayed report did not mark dependency coverage partial: %q", output.String())
			}
			if strings.Contains(output.String(), "private-local-project") {
				t.Errorf("CLI output exposed the local project path: %q", output.String())
			}
		})
	}
}

func TestExitCodeSemantics(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "clean", want: 0},
		{name: "findings", err: FindingsError{Count: 1}, want: 2},
		{name: "partial or execution error", err: errors.New("partial report"), want: 1},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := ExitCode(testCase.err); got != testCase.want {
				t.Errorf("ExitCode(%v) = %d, want %d", testCase.err, got, testCase.want)
			}
		})
	}
}

func TestTestCommandRedactsLegacyProjectPath(t *testing.T) {
	deps := defaultTestCommandDependencies()
	deps.scanProject = func(context.Context, string, scanner.Config) (scanner.Result, error) {
		return scanner.Result{
			Report: json.RawMessage(`{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"project":{"path":"C:\\private\\uploaded-project"} }`),
		}, nil
	}
	cmd := newTestCmd(deps)
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"./project"})

	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "indeterminate") {
		t.Fatalf("execute test command error = %v, want indeterminate legacy result", err)
	}
	if strings.Contains(output.String(), "uploaded-project") ||
		!strings.Contains(output.String(), `"path": "."`) {
		t.Errorf("CLI did not redact legacy project path: %q", output.String())
	}
}

func TestTestCommandPreservesArgumentAndFlagValidation(t *testing.T) {
	deps := defaultTestCommandDependencies()
	if err := executeTestCommand(t, deps); err == nil {
		t.Fatal("command without target succeeded, want argument validation error")
	}
	if err := executeTestCommand(t, deps, "./project", "--branch", " "); err == nil {
		t.Fatal("command with invalid branch succeeded, want validation error")
	}
	if err := executeTestCommand(t, deps, "./project", "--env", "INVALID"); err == nil {
		t.Fatal("command with invalid --env succeeded, want validation error")
	}
}

func TestTestCommandDoesNotPrintEnvironmentValues(t *testing.T) {
	deps := defaultTestCommandDependencies()
	cmd := newTestCmd(deps)
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"./project", "--env", "TOKEN=do-not-print-this"})

	if err := cmd.Execute(); ExitCode(err) != 1 {
		t.Fatalf("execute with --env error = %v, want partial-coverage exit code 1", err)
	}
	if strings.Contains(output.String(), "do-not-print-this") {
		t.Errorf("command output contains environment secret: %q", output.String())
	}
}

func TestTestCommandCleanupErrorIsReturned(t *testing.T) {
	cloneDir := t.TempDir()
	cleanupErr := fmt.Errorf("cleanup failed")
	deps := defaultTestCommandDependencies()
	deps.acquireGit = func(context.Context, string, string) (string, error) { return cloneDir, nil }
	deps.removeAll = func(string) error { return cleanupErr }

	err := executeTestCommand(t, deps, "git@github.com:user/project.git")
	if !errors.Is(err, cleanupErr) {
		t.Errorf("execute error = %v, want cleanup error", err)
	}
}
