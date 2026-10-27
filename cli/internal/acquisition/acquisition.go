package acquisition

import (
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
	return acquireGitProject(target, exec.LookPath, runGitClone)
}

type gitLookPathFunc func(string) (string, error)
type gitCloneFunc func(gitPath, target, destination string) ([]byte, error)

func acquireGitProject(target string, lookPath gitLookPathFunc, clone gitCloneFunc) (string, error) {
	if !isSupportedSSHGitTarget(target) {
		return "", fmt.Errorf("unsupported Git target: expected an SSH repository URL")
	}

	gitPath, err := lookPath("git")
	if err != nil {
		return "", fmt.Errorf("Git executable not found; install Git and ensure it is available on PATH: %w", err)
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

	output, err := clone(gitPath, target, absDestination)
	if err != nil {
		cleanupErr := os.RemoveAll(absDestination)
		detail := strings.TrimSpace(strings.ReplaceAll(string(output), target, "<repository>"))
		if detail == "" {
			detail = err.Error()
		}
		if cleanupErr != nil {
			return "", fmt.Errorf("Git clone failed: %s (also failed to clean up temporary directory: %v): %w", detail, cleanupErr, err)
		}
		return "", fmt.Errorf("Git clone failed: %s: %w", detail, err)
	}

	return absDestination, nil
}

func runGitClone(gitPath, target, destination string) ([]byte, error) {
	command := exec.Command(gitPath, "clone", "--", target, destination)
	return command.CombinedOutput()
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
