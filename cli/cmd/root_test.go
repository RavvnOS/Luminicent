package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestRootCommandInitializes(t *testing.T) {
	cmd := NewRootCmd()
	if cmd == nil {
		t.Fatal("root command is nil")
	}
	if cmd.Name() != "luminicent" {
		t.Fatalf("expected command name luminicent, got %q", cmd.Name())
	}
}

func TestVersionCommandWorks(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"version"})

	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("version command returned error: %v", err)
	}

	if !strings.Contains(output.String(), "Luminicent CLI") {
		t.Fatalf("expected version output to mention CLI, got %q", output.String())
	}
}

func TestCommandsAreRegistered(t *testing.T) {
	cmd := NewRootCmd()
	registered := map[string]bool{}
	for _, subcmd := range cmd.Commands() {
		registered[subcmd.Name()] = true
	}

	for _, name := range []string{"deploy", "status", "logs", "stop", "cleanup", "analyze", "login", "config", "version"} {
		if !registered[name] {
			t.Fatalf("expected command %q to be registered", name)
		}
	}
}

func TestRootCommandDoesNotPanicOnInit(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("root command panicked during initialization: %v", r)
		}
	}()

	_ = NewRootCmd()
	_ = os.Stdout
}
