package envconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name: "valid entries and supported syntax",
			content: `# credentials

KEY=value
export OTHER_KEY=another value
SINGLE_QUOTED='a value with spaces'
DOUBLE_QUOTED="a value with spaces"
INLINE_COMMENT=value # explanation
`,
		},
		{
			name:    "comments and blank lines",
			content: "\n  # comment\n\t\n",
		},
		{
			name:    "malformed entry reports line",
			content: "VALID=value\nnot-an-entry\n",
			wantErr: "line 2",
		},
		{
			name:    "invalid variable name reports line",
			content: "1INVALID=value\n",
			wantErr: "line 1",
		},
		{
			name:    "unterminated quoted value reports line",
			content: "SECRET=top-secret\nVALUE=\"not closed\n",
			wantErr: "line 2",
		},
		{
			name:    "unexpected text after quoted value",
			content: "VALUE='quoted' trailing\n",
			wantErr: "line 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "project.env")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}

			err := ValidateFile(path)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateFile() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateFile() error = nil, want %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ValidateFile() error = %q, want it to contain %q", err, tt.wantErr)
			}
			if strings.Contains(err.Error(), "top-secret") {
				t.Errorf("ValidateFile() error exposed a secret value: %v", err)
			}
		})
	}
}

func TestValidateFileInvalidPaths(t *testing.T) {
	tests := []struct {
		name string
		path func(t *testing.T) string
	}{
		{
			name: "empty path",
			path: func(*testing.T) string { return "" },
		},
		{
			name: "whitespace path",
			path: func(*testing.T) string { return " \t " },
		},
		{
			name: "missing file",
			path: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "missing.env")
			},
		},
		{
			name: "directory",
			path: func(t *testing.T) string {
				return t.TempDir()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateFile(tt.path(t)); err == nil {
				t.Fatal("ValidateFile() error = nil, want an error")
			}
		})
	}
}

func TestValidateFileDoesNotExposeSecretValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.env")
	if err := os.WriteFile(path, []byte("SECRET_VALUE=do-not-show-this\nbad entry\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := ValidateFile(path)
	if err == nil {
		t.Fatal("ValidateFile() error = nil, want malformed-entry error")
	}
	if strings.Contains(err.Error(), "do-not-show-this") {
		t.Errorf("ValidateFile() error exposed a secret value: %v", err)
	}
}
