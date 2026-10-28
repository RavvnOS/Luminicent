package acquisition

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"
)

type TargetType string

const (
	LocalTarget TargetType = "local"
	GitTarget   TargetType = "git"
)

func DetectTarget(target string) TargetType {
	// Git SSH format:
	// git@github.com:user/project.git
	if strings.HasPrefix(target, "git@") {
		return GitTarget
	}

	// Git URL formats:
	// ssh://git@github.com/user/project.git
	// https://github.com/user/project.git
	if parsed, err := url.Parse(target); err == nil {
		switch parsed.Scheme {
		case "git", "ssh", "https", "http":
			return GitTarget
		}
	}

	return LocalTarget
}

func AcquireLocalProject(target string) (string, error) {
	if strings.TrimSpace(target) == "" {
		return "", fmt.Errorf("local project path cannot be empty")
	}

	absPath, err := filepath.Abs(target)
	if err != nil {
		return "", fmt.Errorf("resolve local project path %q: %w", target, err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("local project path %q does not exist: %w", target, err)
		}
		return "", fmt.Errorf("stat local project path %q: %w", target, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("local project path %q is not a directory", target)
	}

	if _, err := os.ReadDir(absPath); err != nil {
		return "", fmt.Errorf("read local project directory %q: %w", absPath, err)
	}

	return absPath, nil
}

func AcquireGitProject(target string) (string, error) {
	return AcquireGitProjectContext(context.Background(), target, "")
}

func AcquireGitProjectBranch(target, branch string) (string, error) {
	return AcquireGitProjectContext(context.Background(), target, branch)
}

func AcquireGitProjectContext(ctx context.Context, target, branch string) (string, error) {
	return acquireGitProject(ctx, target, branch, exec.LookPath, runGitCommand)
}

type gitLookPathFunc func(string) (string, error)
type gitCommandFunc func(context.Context, string, ...string) ([]byte, error)

func acquireGitProject(ctx context.Context, target, branch string, lookPath gitLookPathFunc, run gitCommandFunc) (string, error) {
	if ctx == nil {
		return "", fmt.Errorf("Git acquisition context cannot be nil")
	}
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("Git acquisition cancelled: %w", err)
	}
	if !isSupportedSSHGitTarget(target) {
		return "", fmt.Errorf("unsupported Git target: expected an SSH repository URL")
	}
	if branch != "" {
		if err := ValidateBranchName(branch); err != nil {
			return "", err
		}
	}

	gitPath, err := lookPath("git")
	if err != nil {
		return "", fmt.Errorf("Git executable not found; install Git and ensure it is available on PATH: %w", err)
	}
	if branch != "" {
		if _, err := run(ctx, gitPath, "check-ref-format", "--branch", branch); err != nil {
			return "", fmt.Errorf("invalid Git branch name")
		}
	}
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("Git acquisition cancelled: %w", err)
	}

	destination, err := os.MkdirTemp("", "luminicent-git-*")
	if err != nil {
		return "", fmt.Errorf("create temporary directory for Git clone: %w", err)
	}

	absDestination, err := filepath.Abs(destination)
	if err != nil {
		if cleanupErr := os.RemoveAll(destination); cleanupErr != nil {
			return "", fmt.Errorf("resolve clone directory path: %w (also failed to clean up temporary directory: %v)", err, cleanupErr)
		}
		return "", fmt.Errorf("resolve clone directory path: %w", err)
	}

	cloneArgs := []string{"clone"}
	if branch != "" {
		cloneArgs = append(cloneArgs, "--single-branch", "--branch="+branch)
	}
	cloneArgs = append(cloneArgs, "--", target, absDestination)
	output, err := run(ctx, gitPath, cloneArgs...)
	if err != nil {
		cleanupErr := os.RemoveAll(absDestination)
		detail := "Git clone failed"
		if branch != "" {
			detail = fmt.Sprintf("Git clone failed for branch %q", branch)
			if isMissingRemoteBranch(output) {
				detail = fmt.Sprintf("Git branch %q was not found on the remote", branch)
			}
		}
		if contextErr := ctx.Err(); contextErr != nil {
			err = errors.Join(contextErr, err)
		}
		if cleanupErr != nil {
			return "", fmt.Errorf("%s (also failed to clean up temporary directory: %v): %w", detail, cleanupErr, err)
		}
		return "", fmt.Errorf("%s: %w", detail, err)
	}
	return absDestination, nil
}

func runGitCommand(ctx context.Context, gitPath string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, gitPath, args...)
	return command.CombinedOutput()
}

func isMissingRemoteBranch(output []byte) bool {
	message := strings.ToLower(string(output))
	return (strings.Contains(message, "remote branch") && strings.Contains(message, "not found")) ||
		strings.Contains(message, "couldn't find remote ref")
}

func ValidateBranchName(branch string) error {
	if branch == "" || strings.TrimSpace(branch) != branch ||
		strings.IndexFunc(branch, func(r rune) bool {
			return unicode.IsSpace(r) || unicode.IsControl(r)
		}) >= 0 ||
		strings.HasPrefix(branch, "-") || strings.HasPrefix(branch, "/") ||
		strings.HasSuffix(branch, "/") || strings.HasSuffix(branch, ".") ||
		strings.Contains(branch, "..") || strings.Contains(branch, "//") ||
		strings.Contains(branch, "@{") || branch == "@" {
		return fmt.Errorf("invalid Git branch name")
	}
	for _, component := range strings.Split(branch, "/") {
		if component == "" || strings.HasPrefix(component, ".") ||
			strings.HasSuffix(component, ".lock") {
			return fmt.Errorf("invalid Git branch name")
		}
		for _, character := range component {
			if strings.ContainsRune(" ~^:?*[\\", character) {
				return fmt.Errorf("invalid Git branch name")
			}
		}
	}
	return nil
}

func isSupportedSSHGitTarget(target string) bool {
	if target == "" || strings.TrimSpace(target) != target || strings.IndexFunc(target, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0 {
		return false
	}

	if strings.HasPrefix(target, "ssh://") {
		parsed, err := url.Parse(target)
		if err != nil || parsed.Scheme != "ssh" || parsed.Opaque != "" ||
			parsed.Hostname() == "" || parsed.Path == "" || parsed.RawQuery != "" ||
			parsed.Fragment != "" || !validSSHHost(parsed.Hostname()) {
			return false
		}
		if parsed.User != nil {
			if _, hasPassword := parsed.User.Password(); hasPassword {
				return false
			}
		}
		return true
	}

	if strings.Contains(target, "://") {
		return false
	}

	separator := strings.IndexByte(target, ':')
	if separator <= 0 || separator == len(target)-1 {
		return false
	}

	authority := target[:separator]
	parsed, err := url.Parse("ssh://" + authority)
	if err != nil || parsed.Hostname() == "" || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || !validSSHHost(parsed.Hostname()) {
		return false
	}
	if parsed.User != nil {
		if _, hasPassword := parsed.User.Password(); hasPassword {
			return false
		}
	}
	return true
}

func validSSHHost(host string) bool {
	if strings.HasPrefix(host, "-") {
		return false
	}
	for _, r := range host {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' || r == '_' || r == ':') {
			return false
		}
	}
	return true
}
