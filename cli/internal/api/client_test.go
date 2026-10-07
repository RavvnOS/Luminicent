package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestClientHealth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/health" {
			t.Fatalf("expected /api/health, got %s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true,"status":"healthy","timestamp":"2024-01-01T00:00:00Z"}`)
	}))
	defer server.Close()

	client := NewClient(server.URL, server.Client())
	resp, err := client.Health(context.Background())
	if err != nil {
		t.Fatalf("Health returned error: %v", err)
	}
	if !resp.OK {
		t.Fatal("expected ok=true")
	}
	if resp.Status != "healthy" {
		t.Fatalf("expected healthy status, got %q", resp.Status)
	}
}

func TestClientCleanup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cleanup" {
			t.Fatalf("expected /api/cleanup, got %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}
		if !strings.Contains(string(body), "\"sessionId\":\"abc123\"") {
			t.Fatalf("expected sessionId in request body, got %s", string(body))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"sessionId":"abc123","message":"Simulation stopped"}`)
	}))
	defer server.Close()

	client := NewClient(server.URL, server.Client())
	resp, err := client.Cleanup(context.Background(), "abc123")
	if err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	if !resp.Success {
		t.Fatal("expected success=true")
	}
	if resp.SessionID != "abc123" {
		t.Fatalf("expected session id abc123, got %q", resp.SessionID)
	}
}

func TestClientUpload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/upload" {
			t.Fatalf("expected /api/upload, got %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if err := r.ParseMultipartForm(1024 * 1024); err != nil {
			t.Fatalf("failed to parse multipart form: %v", err)
		}
		if _, ok := r.MultipartForm.Value["sessionId"]; !ok {
			t.Fatal("expected sessionId form value")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"sessionId":"sess-1","message":"Simulation completed"}`)
	}))
	defer server.Close()

	path := writeTempZip(t)
	client := NewClient(server.URL, server.Client())
	resp, err := client.Upload(context.Background(), path, "sess-1")
	if err != nil {
		t.Fatalf("Upload returned error: %v", err)
	}
	if !resp.Success {
		t.Fatal("expected success=true")
	}
	if resp.SessionID != "sess-1" {
		t.Fatalf("expected sess-1, got %q", resp.SessionID)
	}
}

func TestClientGitHubDeploy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/github/deploy" {
			t.Fatalf("expected /api/github/deploy, got %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Cookie"); got == "" {
			t.Fatal("expected session cookie header")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}
		if !strings.Contains(string(body), "\"owner\":\"octo\"") || !strings.Contains(string(body), "\"repo\":\"demo\"") || !strings.Contains(string(body), "\"branch\":\"main\"") {
			t.Fatalf("expected deploy payload fields, got %s", string(body))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"sessionId":"gh-99","message":"Simulation started"}`)
	}))
	defer server.Close()

	client := NewClient(server.URL, server.Client())
	client.SessionCookie = "luminicent_github_session=token-value"
	resp, err := client.DeployGitHubRepo(context.Background(), "octo", "demo", "main", "gh-99")
	if err != nil {
		t.Fatalf("DeployGitHubRepo returned error: %v", err)
	}
	if !resp.Success {
		t.Fatal("expected success=true")
	}
	if resp.SessionID != "gh-99" {
		t.Fatalf("expected gh-99, got %q", resp.SessionID)
	}
}

func TestClientListDeployments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/github/deployments" {
			t.Fatalf("expected /api/github/deployments, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"sessionId":"one","status":"RUNNING","startedAt":1700000000000}]`)
	}))
	defer server.Close()

	client := NewClient(server.URL, server.Client())
	resp, err := client.ListDeployments(context.Background())
	if err != nil {
		t.Fatalf("ListDeployments returned error: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("expected 1 deployment, got %d", len(resp))
	}
	if resp[0].SessionID != "one" {
		t.Fatalf("expected session id one, got %q", resp[0].SessionID)
	}
}

func TestClientAnalysisNotImplemented(t *testing.T) {
	client := NewClient("http://example.com", http.DefaultClient)
	if err := client.Analyze(context.Background(), "demo", "main"); err == nil {
		t.Fatal("expected Analyze to return not implemented error")
	}
}

func writeTempZip(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/app.zip"
	if err := os.WriteFile(path, []byte("zip-data"), 0o600); err != nil {
		t.Fatalf("failed to write temp zip: %v", err)
	}
	return path
}
