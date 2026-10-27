package envconfig

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func ValidateFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("environment file path cannot be empty")
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open environment file %q: %w", path, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat environment file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("environment file %q is not a regular file", path)
	}

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if err := validateLine(scanner.Text()); err != nil {
			return fmt.Errorf("environment file %q, line %d: %w", path, lineNumber, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read environment file %q after line %d: %w", path, lineNumber, err)
	}

	return nil
}

func validateLine(line string) error {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	if strings.HasPrefix(line, "export ") || strings.HasPrefix(line, "export\t") {
		line = strings.TrimSpace(line[len("export"):])
	}

	separator := strings.IndexByte(line, '=')
	if separator < 0 {
		return fmt.Errorf("malformed entry: expected KEY=value")
	}

	key := strings.TrimSpace(line[:separator])
	if !validKey(key) {
		return fmt.Errorf("invalid environment variable name")
	}

	return validateValue(strings.TrimSpace(line[separator+1:]))
}

func validKey(key string) bool {
	if key == "" {
		return false
	}
	for i, r := range key {
		if i == 0 {
			if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
				return false
			}
			continue
		}
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func validateValue(value string) error {
	if value == "" || strings.HasPrefix(value, "#") {
		return nil
	}

	quote := value[0]
	if quote != '\'' && quote != '"' {
		if strings.ContainsAny(value, "'\"") {
			return fmt.Errorf("malformed value: quote must enclose the entire value")
		}
		return nil
	}

	escaped := false
	closeIndex := -1
	for i := 1; i < len(value); i++ {
		char := value[i]
		if quote == '"' && char == '\\' && !escaped {
			escaped = true
			continue
		}
		if char == quote && !escaped {
			closeIndex = i
			break
		}
		escaped = false
	}
	if closeIndex < 0 {
		return fmt.Errorf("malformed value: unterminated quoted value")
	}

	remainder := strings.TrimSpace(value[closeIndex+1:])
	if remainder != "" && !strings.HasPrefix(remainder, "#") {
		return fmt.Errorf("malformed value: unexpected text after quoted value")
	}
	return nil
}
