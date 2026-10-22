package acquisition

import (
	"net/url"
	"strings"
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

	// Git URL format:
	// ssh://git@github.com/user/project.git
	// https://github.com/user/project.git
	if parsed, err := url.Parse(target); err == nil {
		if parsed.Scheme == "git" ||
			parsed.Scheme == "ssh" ||
			parsed.Scheme == "https" ||
			parsed.Scheme == "http" {
			return GitTarget
		}
	}

	return LocalTarget
}
