package acquisition

import (
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
			gotPath, err := acquireGitProject(tt.target, lookPath, nil)
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

	gotPath, err := acquireGitProject("git@github.com:user/project.git", lookPath, nil)
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
	clone := func(_, target, dest string) ([]byte, error) {
		destination = dest
		if target != "git@github.com:user/project.git" {
			t.Errorf("clone target = %q, want supplied SSH URL", target)
		}
		if err := os.WriteFile(filepath.Join(dest, "partial"), []byte("partial"), 0o600); err != nil {
			t.Fatalf("create partial clone: %v", err)
		}
		return []byte("fatal: unable to access git@github.com:user/project.git"), cloneErr
	}

	gotPath, err := acquireGitProject("git@github.com:user/project.git", func(string) (string, error) {
		return "git", nil
	}, clone)
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
	var gotTarget string
	clone := func(gitPath, cloneTarget, destination string) ([]byte, error) {
		if gitPath != "fake-git" {
			t.Errorf("clone executable = %q, want fake-git", gitPath)
		}
		gotTarget = cloneTarget
		if err := os.WriteFile(filepath.Join(destination, "README.md"), []byte("project"), 0o600); err != nil {
			t.Fatalf("create cloned project: %v", err)
		}
		return nil, nil
	}

	gotPath, err := acquireGitProject(target, func(name string) (string, error) {
		if name != "git" {
			t.Errorf("lookPath() name = %q, want git", name)
		}
		return "fake-git", nil
	}, clone)
	if err != nil {
		t.Fatalf("acquireGitProject() error = %v, want nil", err)
	}
	if gotTarget != target {
		t.Errorf("clone target = %q, want %q", gotTarget, target)
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
