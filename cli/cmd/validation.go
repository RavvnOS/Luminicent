package cmd

import (
	"fmt"
	"strings"
)

func validateKeyValueList(values []string, flagName string) error {
	for _, value := range values {
		if value == "" {
			return fmt.Errorf("%s values must be in KEY=VALUE format", flagName)
		}
		parts := strings.SplitN(value, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
			return fmt.Errorf("%s values must be in KEY=VALUE format: %q", flagName, value)
		}
	}
	return nil
}

func validateBranch(branch string) error {
	if strings.TrimSpace(branch) == "" {
		return fmt.Errorf("--branch must not be empty")
	}
	return nil
}
