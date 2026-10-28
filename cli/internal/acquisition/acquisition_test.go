package acquisition

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAcquireLocalProject(t *testing.T) {
	tests := []struct {
		name    string
		target  func(t *testing.T) string
		wantErr bool
	}{
		{
			name: "existing directory",
			target: func(t *testing.T) string {
				return t.TempDir()
			},
		},
		{
			name: "empty path",
			target: func(t *testing.T) string {
				return ""
			},
			wantErr: true,
		},
		{
			name: "whitespace-only path",
			target: func(t *testing.T) string {
				return " \t\n "
			},
			wantErr: true,
		},
		{
			name: "nonexistent directory",
			target: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "missing")
			},
			wantErr: true,
		},
		{
			name: "regular file",
			target: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "project.txt")
				if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			},
			wantErr: true,
		},
		{
			name: "relative directory",
			target: func(t *testing.T) string {
				dir := t.TempDir()
				workingDir, err := os.Getwd()
				if err != nil {
					t.Fatal(err)
				}
				relativePath, err := filepath.Rel(workingDir, dir)
				if err != nil {
					t.Fatal(err)
				}
				return relativePath
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := tt.target(t)
			gotPath, err := AcquireLocalProject(target)

			if tt.wantErr {
				if err == nil {
					t.Fatal("AcquireLocalProject() error = nil, want an error")
				}
				if gotPath != "" {
					t.Errorf("AcquireLocalProject() path = %q, want empty on error", gotPath)
				}
				return
			}

			if err != nil {
				t.Fatalf("AcquireLocalProject() error = %v, want nil", err)
			}
			wantPath, err := filepath.Abs(target)
			if err != nil {
				t.Fatalf("filepath.Abs(%q) error = %v", target, err)
			}
			if gotPath != wantPath {
				t.Errorf("AcquireLocalProject() path = %q, want %q", gotPath, wantPath)
			}
		})
	}
}

func TestAcquireGitProjectInvalidTargets(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{name: "empty", target: ""},
		{name: "whitespace", target: " \t "},
		{name: "local path", target: "./project"},
		{name: "HTTPS URL", target: "https://github.com/user/project.git"},
		{name: "missing repository path", target: "git@github.com:"},
		{name: "SSH password", target: "ssh://user:password@github.com/user/project.git"},
		{name: "unsupported scheme", target: "git://github.com/user/project.git"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookPath := func(string) (string, error) {
				t.Fatal("Git lookup must not run for an invalid target")
				return "", nil
			}
			gotPath, err := acquireGitProject(context.Background(), tt.target, "", lookPath, nil)
			if err == nil {
				t.Fatal("acquireGitProject() error = nil, want an error")
			}
			if gotPath != "" {
				t.Errorf("acquireGitProject() path = %q, want empty on error", gotPath)
			}
		})
	}
}

func TestAcquireGitProjectMissingGit(t *testing.T) {
	wantErr := errors.New("executable file not found")
	lookPath := func(name string) (string, error) {
		if name != "git" {
			t.Errorf("lookPath() name = %q, want git", name)
		}
		return "", wantErr
	}

	gotPath, err := acquireGitProject(context.Background(), "git@github.com:user/project.git", "", lookPath, nil)
	if err == nil {
		t.Fatal("acquireGitProject() error = nil, want an error")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("acquireGitProject() error = %v, want wrapped missing-Git error", err)
	}
	if !strings.Contains(err.Error(), "Git executable not found") {
		t.Errorf("acquireGitProject() error = %q, want clear Git-not-found context", err)
	}
	if gotPath != "" {
		t.Errorf("acquireGitProject() path = %q, want empty on error", gotPath)
	}
}

func TestAcquireGitProjectCloneFailureCleansUp(t *testing.T) {
	cloneErr := errors.New("exit status 1")
	var destination string
	run := func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) < 4 || args[0] != "clone" {
			t.Fatalf("unexpected git args: %q", args)
		}
		target, dest := args[len(args)-2], args[len(args)-1]
		destination = dest
		if target != "git@github.com:user/project.git" {
			t.Errorf("clone target = %q, want supplied SSH URL", target)
		}
		if err := os.WriteFile(filepath.Join(dest, "partial"), []byte("partial"), 0o600); err != nil {
			t.Fatalf("create partial clone: %v", err)
		}
		return []byte("fatal: unable to access git@github.com:user/project.git"), cloneErr
	}

	gotPath, err := acquireGitProject(context.Background(), "git@github.com:user/project.git", "", func(string) (string, error) {
		return "git", nil
	}, run)
	if err == nil {
		t.Fatal("acquireGitProject() error = nil, want an error")
	}
	if !errors.Is(err, cloneErr) {
		t.Errorf("acquireGitProject() error = %v, want wrapped clone error", err)
	}
	if gotPath != "" {
		t.Errorf("acquireGitProject() path = %q, want empty on error", gotPath)
	}
	if strings.Contains(err.Error(), "git@github.com:user/project.git") {
		t.Errorf("acquireGitProject() error exposes the repository URL: %v", err)
	}
	if _, statErr := os.Stat(destination); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("clone destination still exists after failure; stat error = %v", statErr)
	}
}

func TestAcquireGitProjectSuccess(t *testing.T) {
	target := "ssh://git@github.com/user/project.git"
	run := func(_ context.Context, gitPath string, args ...string) ([]byte, error) {
		if gitPath != "fake-git" {
			t.Errorf("clone executable = %q, want fake-git", gitPath)
		}
		if len(args) != 4 || args[0] != "clone" || args[1] != "--" {
			t.Fatalf("unexpected Git clone arguments: %q", args)
		}
		if args[2] != target {
			t.Errorf("clone target = %q, want %q", args[2], target)
		}
		destination := args[3]
		if err := os.WriteFile(filepath.Join(destination, "README.md"), []byte("project"), 0o600); err != nil {
			t.Fatalf("create cloned project: %v", err)
		}
		return nil, nil
	}

	gotPath, err := acquireGitProject(context.Background(), target, "", func(name string) (string, error) {
		if name != "git" {
			t.Errorf("lookPath() name = %q, want git", name)
		}
		return "fake-git", nil
	}, run)
	if err != nil {
		t.Fatalf("acquireGitProject() error = %v, want nil", err)
	}
	if !filepath.IsAbs(gotPath) {
		t.Errorf("acquireGitProject() path = %q, want absolute path", gotPath)
	}
	if _, err := os.Stat(filepath.Join(gotPath, "README.md")); err != nil {
		t.Errorf("cloned file missing from returned directory: %v", err)
	}
	if err := os.RemoveAll(gotPath); err != nil {
		t.Errorf("remove test clone directory: %v", err)
	}
}

func TestAcquireGitProjectUsesAndChecksRequestedBranch(t *testing.T) {
	const target = "git@github.com:user/project.git"
	const branch = "release/phase-3"
	var calls [][]string
	run := func(_ context.Context, _ string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if args[0] == "clone" {
			if err := os.WriteFile(filepath.Join(args[len(args)-1], "README.md"), []byte(branch), 0o600); err != nil {
				t.Fatalf("create cloned project: %v", err)
			}
		}
		return nil, nil
	}

	gotPath, err := acquireGitProject(context.Background(), target, branch, func(string) (string, error) {
		return "fake-git", nil
	}, run)
	if err != nil {
		t.Fatalf("acquireGitProject() error = %v", err)
	}
	defer os.RemoveAll(gotPath)

	wantCalls := [][]string{
		{"check-ref-format", "--branch", branch},
		{"clone", "--single-branch", "--branch=" + branch, "--", target, gotPath},
	}
	if len(calls) != len(wantCalls) {
		t.Fatalf("Git calls = %q, want %q", calls, wantCalls)
	}
	for index := range wantCalls {
		if strings.Join(calls[index], "\x00") != strings.Join(wantCalls[index], "\x00") {
			t.Errorf("Git call %d = %q, want %q", index, calls[index], wantCalls[index])
		}
	}
	contents, err := os.ReadFile(filepath.Join(gotPath, "README.md"))
	if err != nil || string(contents) != branch {
		t.Errorf("clone contents = %q, %v; want selected branch marker %q", contents, err, branch)
	}
}

func TestAcquireGitProjectRejectsInvalidAndMissingBranches(t *testing.T) {
	t.Run("invalid branch name", func(t *testing.T) {
		runCalled := false
		_, err := acquireGitProject(context.Background(), "git@github.com:user/project.git", "release..bad",
			func(string) (string, error) { return "fake-git", nil },
			func(context.Context, string, ...string) ([]byte, error) {
				runCalled = true
				return nil, nil
			})
		if err == nil || !strings.Contains(err.Error(), "invalid Git branch name") {
			t.Fatalf("branch error = %v, want invalid branch message", err)
		}

		if runCalled {
			t.Fatal("Git was invoked for a syntactically invalid branch")
		}
	})

	t.Run("branch rejected by Git", func(t *testing.T) {
		var calls int
		_, err := acquireGitProject(context.Background(), "git@github.com:user/project.git", "release",
			func(string) (string, error) { return "fake-git", nil },
			func(_ context.Context, _ string, args ...string) ([]byte, error) {
				calls++
				if args[0] != "check-ref-format" {
					t.Errorf("Git call = %q, want branch validation first", args)
				}
				return []byte("private git diagnostics"), errors.New("exit status 1")
			})
		if err == nil || !strings.Contains(err.Error(), "invalid Git branch name") {
			t.Fatalf("branch error = %v, want invalid branch message", err)
		}
		if strings.Contains(err.Error(), "private git diagnostics") || calls != 1 {
			t.Errorf("branch validation leaked output or continued: calls=%d error=%v", calls, err)
		}
	})

	t.Run("nonexistent branch", func(t *testing.T) {
		var destination string
		run := func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if args[0] == "clone" {
				destination = args[len(args)-1]
				return []byte("fatal: Remote branch missing not found"), errors.New("exit status 128")
			}
			return nil, nil
		}
		_, err := acquireGitProject(context.Background(), "git@github.com:user/project.git", "missing",
			func(string) (string, error) { return "fake-git", nil }, run)
		if err == nil || !strings.Contains(err.Error(), `branch "missing" was not found on the remote`) {
			t.Fatalf("missing branch error = %v, want branch-specific failure", err)
		}
		if strings.Contains(err.Error(), "Remote branch") {
			t.Errorf("Git stderr was exposed: %v", err)
		}
		if _, statErr := os.Stat(destination); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("failed clone directory was not removed: %v", statErr)
		}
	})
}

func TestAcquireGitProjectCancellationCleansPartialClone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var destination string
	run := func(ctx context.Context, _ string, args ...string) ([]byte, error) {
		destination = args[len(args)-1]
		if err := os.WriteFile(filepath.Join(destination, "partial"), []byte("partial"), 0o600); err != nil {
			t.Fatalf("create partial clone: %v", err)
		}
		cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	}

	_, err := acquireGitProject(ctx, "git@github.com:user/project.git", "",
		func(string) (string, error) { return "fake-git", nil }, run)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("acquisition error = %v, want context cancellation", err)
	}
	if _, statErr := os.Stat(destination); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("partial clone remains after cancellation: %v", statErr)
	}
}
