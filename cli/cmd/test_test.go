package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arvind-git04/Luminicent/cli/internal/acquisition"
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
		cmd := NewTestCmd()
		projectDir := t.TempDir()
		envFile := filepath.Join(t.TempDir(), "project.env")
		if err := os.WriteFile(envFile, []byte("KEY=value\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(&output)
		cmd.SetArgs([]string{projectDir, "--env-file", envFile})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("execute with --env-file: %v", err)
		}
		gotEnvFile, err := cmd.Flags().GetString("env-file")
		if err != nil {
			t.Fatalf("get --env-file: %v", err)
		}
		if gotEnvFile != envFile {
			t.Errorf("--env-file = %q, want %q", gotEnvFile, envFile)
		}
		if !strings.Contains(output.String(), "Test target: "+projectDir+"\n") {
			t.Errorf("command output does not retain target: %q", output.String())
		}
	})

	t.Run("flag is optional", func(t *testing.T) {
		cmd := NewTestCmd()
		projectDir := t.TempDir()
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(&output)
		cmd.SetArgs([]string{projectDir})

		if err := cmd.Execute(); err != nil {
			t.Fatalf("execute without --env-file: %v", err)
		}
		if !strings.Contains(output.String(), "Test target: "+projectDir+"\n") {
			t.Errorf("command output does not retain target: %q", output.String())
		}
	})
}

func defaultTestCommandDependencies() testCommandDependencies {
	return testCommandDependencies{
		detectTarget: acquisition.DetectTarget,
		acquireLocal: func(target string) (string, error) {
			return target, nil
		},
		acquireGit: func(string) (string, error) {
			return "", errors.New("unexpected Git acquisition")
		},
		validateEnvFile: func(string) error { return nil },
		absPath:         filepath.Abs,
		stat:            os.Stat,
		removeAll:       os.RemoveAll,
	}
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

	if err := executeTestCommand(t, deps, "./local-project"); err != nil {
		t.Fatalf("execute test command: %v", err)
	}
	if !localCalled {
		t.Fatal("local acquisition was not called")
	}
	if validatedPath != envPath {
		t.Errorf("validated environment path = %q, want %q", validatedPath, envPath)
	}
}

func TestTestCommandExplicitEnvFile(t *testing.T) {
	projectDir := t.TempDir()
	explicitEnvFile := filepath.Join(t.TempDir(), "explicit.env")
	if err := os.WriteFile(explicitEnvFile, []byte("KEY=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	deps := defaultTestCommandDependencies()
	var validatedPath string
	deps.acquireLocal = func(string) (string, error) { return projectDir, nil }
	deps.validateEnvFile = func(path string) error {
		validatedPath = path
		return nil
	}
	deps.stat = func(string) (os.FileInfo, error) {
		t.Fatal("automatic .env discovery must not run when --env-file is explicit")
		return nil, nil
	}

	if err := executeTestCommand(t, deps, "./local-project", "--env-file", explicitEnvFile); err != nil {
		t.Fatalf("execute with explicit env file: %v", err)
	}
	wantPath, err := filepath.Abs(explicitEnvFile)
	if err != nil {
		t.Fatal(err)
	}
	if validatedPath != wantPath {
		t.Errorf("validated environment path = %q, want absolute path %q", validatedPath, wantPath)
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

	if err := executeTestCommand(t, deps, "./local-project"); err != nil {
		t.Fatalf("execute without local .env: %v", err)
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
	deps.acquireGit = func(target string) (string, error) {
		gitCalled = true
		if target != "git@github.com:user/project.git" {
			t.Errorf("Git acquisition target = %q, want SSH URL", target)
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

	if err := executeTestCommand(t, deps, "git@github.com:user/project.git"); err != nil {
		t.Fatalf("execute Git target: %v", err)
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
		deps.acquireGit = func(string) (string, error) { return "", acquisitionErr }
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
	deps.acquireGit = func(string) (string, error) { return cloneDir, nil }
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

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute with --env: %v", err)
	}
	if strings.Contains(output.String(), "do-not-print-this") {
		t.Errorf("command output contains environment secret: %q", output.String())
	}
}

func TestTestCommandCleanupErrorIsReturned(t *testing.T) {
	cloneDir := t.TempDir()
	cleanupErr := fmt.Errorf("cleanup failed")
	deps := defaultTestCommandDependencies()
	deps.acquireGit = func(string) (string, error) { return cloneDir, nil }
	deps.removeAll = func(string) error { return cleanupErr }

	err := executeTestCommand(t, deps, "git@github.com:user/project.git")
	if !errors.Is(err, cleanupErr) {
		t.Errorf("execute error = %v, want cleanup error", err)
	}
}
