package scanner

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func withCompleteChecks(raw json.RawMessage) json.RawMessage {
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return raw
	}
	isReport := true
	scan, ok := value["scan"].(map[string]any)
	if !ok {
		scan = value
		isReport = false
	}
	checks, _ := scan["checks"].([]any)
	seen := make(map[string]bool)
	for _, rawCheck := range checks {
		if check, ok := rawCheck.(map[string]any); ok {
			if id, ok := check["id"].(string); ok {
				seen[id] = true
			}
		}
	}
	expected := []struct {
		id     string
		status string
	}{
		{"dockerfile_presence", "completed"},
		{"dockerfile_configuration", "completed"},
		{"dockerignore_configuration", "completed"},
		{"environment_configuration", "completed"},
		{"image_metadata", "completed"},
		{"runtime_inspection", "completed"},
		{"secret_pattern_search", "completed"},
		{"insecure_transport_configuration", "completed"},
		{"dangerous_application_configuration", "completed"},
		{"project_structure", "completed"},
		{"owasp_top_10", "unsupported"},
		{"dynamic_vulnerability_testing", "unsupported"},
		{"dependency_vulnerability_analysis", "completed"},
		{"exploit_verification", "unsupported"},
	}
	for _, check := range expected {
		if !seen[check.id] {
			checks = append(checks, map[string]any{
				"id": check.id, "status": check.status,
				"name": check.id, "scope": "test fixture scope",
				"explanation": "test fixture explanation",
			})
		}
	}
	for _, rawCheck := range checks {
		if check, ok := rawCheck.(map[string]any); ok {
			check["name"] = "test check"
			check["scope"] = "test fixture scope"
			check["explanation"] = "test fixture explanation"
		}
	}
	scan["checks"] = checks
	scan["status"] = "partial"
	if isReport {
		value["scan"] = scan
		dependencyStatus := ""
		for _, rawCheck := range checks {
			if check, ok := rawCheck.(map[string]any); ok && check["id"] == "dependency_vulnerability_analysis" {
				dependencyStatus, _ = check["status"].(string)
			}
		}
		if dependencyStatus == "completed" && value["dependencyAnalysis"] == nil {
			value["dependencyAnalysis"] = map[string]any{
				"source": "OSV", "status": "completed", "packageCount": 0,
				"queriedPackageCount": 0, "advisoryCount": 0,
			}
		}
	}
	updated, err := json.Marshal(value)
	if err != nil {
		return raw
	}
	return updated
}

func newSessionTestServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/api/sessions") {
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer test-api-token" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"sessionId":"test-session","sessionToken":"test-session-capability"}`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/api/cleanup") {
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer test-api-token" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			var credentials sessionCredentials
			if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil ||
				credentials.SessionID != "test-session" ||
				credentials.SessionToken != "test-session-capability" {
				http.Error(w, "invalid cleanup session", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"success":true}`)
			return
		}
		handler.ServeHTTP(w, r)
	}))
}

func TestCreateProjectArchiveUsesRelativePathsAndExcludesSensitiveFiles(t *testing.T) {
	project := t.TempDir()
	writeProjectFile(t, project, "package.json", `{"name":"example"}`)
	writeProjectFile(t, project, "src/main.go", "package main")
	writeProjectFile(t, project, ".env", "TOKEN=do-not-archive")
	writeProjectFile(t, project, ".env.example", "TOKEN=example")
	writeProjectFile(t, project, "project.env", "TOKEN=also-private")
	writeProjectFile(t, project, "credentials.json", `{"token":"private"}`)
	writeProjectFile(t, project, ".ssh/id_rsa", "private-key")
	writeProjectFile(t, project, ".aws/credentials", "aws secret")
	writeProjectFile(t, project, "keys/id_ed25519", "private-key")
	writeProjectFile(t, project, "keys/client.pem", "private-key")
	writeProjectFile(t, project, "nested/private.env", "TOKEN=nested")
	writeProjectFile(t, project, ".git/config", "git metadata")
	writeProjectFile(t, project, "node_modules/pkg/index.js", "dependency")
	customEnvFile := writeProjectFile(t, project, "local-settings.txt", "TOKEN=custom-env-file")
	writeProjectFile(t, project, "excluded-dir/private.txt", "do-not-archive")
	writeProjectFile(t, project, "excluded-dir/public.txt", "also-excluded")

	archivePath, err := createProjectArchive(context.Background(), project, []string{
		customEnvFile,
		"excluded-dir",
		filepath.Join(t.TempDir(), "outside", "package.json"),
	})
	if err != nil {
		t.Fatalf("create project archive: %v", err)
	}
	defer os.Remove(archivePath)

	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		t.Fatalf("open project archive: %v", err)
	}
	defer archive.Close()

	entries := make(map[string]string)
	for _, file := range archive.File {
		if filepath.IsAbs(filepath.FromSlash(file.Name)) || strings.HasPrefix(file.Name, "../") {
			t.Errorf("archive contains unsafe path %q", file.Name)
		}
		if file.FileInfo().IsDir() {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			t.Fatalf("open archived file %q: %v", file.Name, err)
		}
		content, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil {
			t.Fatalf("read archived file %q: %v", file.Name, err)
		}
		entries[file.Name] = string(content)
	}

	if entries["package.json"] != `{"name":"example"}` {
		t.Errorf("root-level file was not preserved: %#v", entries)
	}
	if entries["src/main.go"] != "package main" {
		t.Errorf("nested relative path was not preserved: %#v", entries)
	}
	if _, exists := entries["nested/private.env"]; exists {
		t.Errorf("nested sensitive environment file was archived: %#v", entries)
	}
	if _, exists := entries["excluded-dir/private.txt"]; exists {
		t.Errorf("explicitly excluded directory was archived: %#v", entries)
	}
	if len(entries) != 2 {
		t.Errorf("archive contains unexpected files: %#v", entries)
	}
}

func TestCreateProjectArchiveEnforcesConfiguredLimitsAtBoundaries(t *testing.T) {
	project := t.TempDir()
	writeProjectFile(t, project, "one.txt", "1234")
	writeProjectFile(t, project, "two.txt", "567")

	baseArchive, err := createProjectArchive(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("create baseline archive: %v", err)
	}
	info, err := os.Stat(baseArchive)
	if err != nil {
		t.Fatalf("stat baseline archive: %v", err)
	}
	if err := os.Remove(baseArchive); err != nil {
		t.Fatalf("remove baseline archive: %v", err)
	}

	tests := []struct {
		name    string
		limits  ArchiveLimits
		wantErr string
	}{
		{
			name: "exact compressed, expanded, entry, and file boundaries",
			limits: ArchiveLimits{
				CompressedBytes: info.Size(),
				ExpandedBytes:   7,
				Entries:         2,
				IndividualFile:  4,
			},
		},
		{
			name: "compressed bytes exceeded",
			limits: ArchiveLimits{
				CompressedBytes: info.Size() - 1,
				ExpandedBytes:   7,
				Entries:         2,
				IndividualFile:  4,
			},
			wantErr: "compressed size limit",
		},
		{
			name: "expanded bytes exceeded",
			limits: ArchiveLimits{
				CompressedBytes: info.Size(),
				ExpandedBytes:   6,
				Entries:         2,
				IndividualFile:  4,
			},
			wantErr: "expanded archive size limit",
		},
		{
			name: "entry count exceeded",
			limits: ArchiveLimits{
				CompressedBytes: info.Size(),
				ExpandedBytes:   7,
				Entries:         1,
				IndividualFile:  4,
			},
			wantErr: "archive entry limit",
		},
		{
			name: "individual file exceeded",
			limits: ArchiveLimits{
				CompressedBytes: info.Size(),
				ExpandedBytes:   7,
				Entries:         2,
				IndividualFile:  3,
			},
			wantErr: "per-file size limit",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			archivePath, err := createProjectArchiveWithLimits(
				context.Background(), project, nil, testCase.limits,
			)
			if testCase.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), testCase.wantErr) {
					t.Fatalf("archive error = %v, want %q", err, testCase.wantErr)
				}
				if archivePath != "" {
					t.Errorf("failed archive path = %q, want empty", archivePath)
				}
				return
			}
			if err != nil {
				t.Fatalf("create archive at exact boundaries: %v", err)
			}
			if err := os.Remove(archivePath); err != nil {
				t.Errorf("remove archive: %v", err)
			}
		})
	}
}

func TestResolveArchiveLimitsCannotExceedBackendCaps(t *testing.T) {
	defaults, err := resolveArchiveLimits(ArchiveLimits{})
	if err != nil {
		t.Fatalf("resolve default archive limits: %v", err)
	}
	if defaults.CompressedBytes != 100<<20 || defaults.ExpandedBytes != 1<<30 ||
		defaults.Entries != 10_000 || defaults.IndividualFile != 100<<20 {
		t.Errorf("unexpected default archive limits: %#v", defaults)
	}
	if _, err := resolveArchiveLimits(ArchiveLimits{CompressedBytes: MaxCompressedBytes + 1}); err == nil {
		t.Fatal("archive limits above backend cap were accepted")
	}
	if _, err := resolveArchiveLimits(ArchiveLimits{Entries: -1}); err == nil {
		t.Fatal("negative archive entry limit was accepted")
	}
}

func TestCreateProjectArchiveRejectsSymlinks(t *testing.T) {
	project := t.TempDir()
	outside := writeProjectFile(t, t.TempDir(), "outside.txt", "outside")
	link := filepath.Join(project, "linked.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	if _, err := createProjectArchive(context.Background(), project, nil); err == nil ||
		!strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("create archive error = %v, want symlink rejection", err)
	}
}

func TestCreateProjectArchiveRejectsSymlinkRoot(t *testing.T) {
	project := t.TempDir()
	link := filepath.Join(t.TempDir(), "project-link")
	if err := os.Symlink(project, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	if _, err := createProjectArchive(context.Background(), link, nil); err == nil ||
		!strings.Contains(err.Error(), "non-symlink directory") {
		t.Fatalf("archive root error = %v, want symlink root rejection", err)
	}
}

func TestCreateProjectArchiveRemovesPartialArchiveAfterLimitOrCancellation(t *testing.T) {
	project := t.TempDir()
	writeProjectFile(t, project, "source.txt", strings.Repeat("data", 1024))
	tempRoot := t.TempDir()
	t.Setenv("TMP", tempRoot)
	t.Setenv("TEMP", tempRoot)

	_, err := createProjectArchiveWithLimits(context.Background(), project, nil, ArchiveLimits{
		CompressedBytes: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "compressed size limit") {
		t.Fatalf("compressed limit error = %v", err)
	}
	entries, err := os.ReadDir(tempRoot)
	if err != nil {
		t.Fatalf("read temp directory: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("partial archive was not removed: %v", entries)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = createProjectArchive(ctx, project, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("archive cancellation error = %v, want context cancellation", err)
	}
	entries, err = os.ReadDir(tempRoot)
	if err != nil {
		t.Fatalf("read temp directory after cancellation: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("archive remained after cancellation: %v", entries)
	}
}

func TestCreateProjectArchiveRejectsNonDirectoryAndCancellation(t *testing.T) {
	projectFile := writeProjectFile(t, t.TempDir(), "file", "content")
	if _, err := createProjectArchive(context.Background(), projectFile, nil); err == nil {
		t.Fatal("archive accepted a non-directory project path")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := createProjectArchive(ctx, t.TempDir(), nil); !errors.Is(err, context.Canceled) {
		t.Errorf("archive cancellation error = %v, want context.Canceled", err)
	}
}

func TestCreateProjectArchiveEnforcesPathDepthBoundary(t *testing.T) {
	for _, testCase := range []struct {
		name           string
		directoryCount int
		wantErr        bool
	}{
		{name: "exact limit", directoryCount: MaxArchivePathDepth - 1},
		{name: "one over limit", directoryCount: MaxArchivePathDepth, wantErr: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			project := t.TempDir()
			parts := make([]string, testCase.directoryCount+1)
			for index := 0; index < testCase.directoryCount; index++ {
				parts[index] = "d"
			}
			parts[len(parts)-1] = "file.txt"
			relative := filepath.Join(parts...)
			writeProjectFile(t, project, relative, "contents")

			archivePath, err := createProjectArchive(context.Background(), project, nil)
			if testCase.wantErr {
				if err == nil || !strings.Contains(err.Error(), "maximum archive path depth") {
					t.Fatalf("archive error = %v, want path-depth rejection", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("archive at exact path-depth limit: %v", err)
			}
			if removeErr := os.Remove(archivePath); removeErr != nil {
				t.Errorf("remove archive: %v", removeErr)
			}
		})
	}
}

func TestClientScanUploadsZipAndParsesBackendReport(t *testing.T) {
	project := t.TempDir()
	writeProjectFile(t, project, "package.json", `{"name":"example"}`)
	writeProjectFile(t, project, ".env", "TOKEN=do-not-send")

	var requestChecked bool
	server := newSessionTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/base/api/sessions" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"sessionId":"test-session","sessionToken":"test-session-capability"}`)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("request method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/base/api/upload" {
			t.Errorf("request path = %q, want /base/api/upload", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-api-token" ||
			r.Header.Get("X-Luminicent-Session-Id") != "test-session" ||
			r.Header.Get("X-Luminicent-Session-Token") != "test-session-capability" {
			t.Errorf("upload request omitted session authentication headers")
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "multipart/form-data" {
			t.Errorf("request content type = %q, want multipart/form-data", r.Header.Get("Content-Type"))
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("parse multipart request: %v", err)
			http.Error(w, "bad multipart", http.StatusBadRequest)
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			t.Errorf("form field file: %v", err)
			http.Error(w, "missing file", http.StatusBadRequest)
			return
		}
		defer file.Close()
		if header.Filename != "project.zip" {
			t.Errorf("upload filename = %q, want project.zip", header.Filename)
		}
		if header.Header.Get("Content-Type") != "application/zip" {
			t.Errorf("file content type = %q, want application/zip", header.Header.Get("Content-Type"))
		}
		uploaded, err := io.ReadAll(file)
		if err != nil {
			t.Errorf("read uploaded zip: %v", err)
		}
		zipReader, err := zip.NewReader(strings.NewReader(string(uploaded)), int64(len(uploaded)))
		if err != nil {
			t.Errorf("uploaded body is not a ZIP: %v", err)
		} else {
			names := make(map[string]bool)
			for _, entry := range zipReader.File {
				names[entry.Name] = true
			}
			if !names["package.json"] || names[".env"] {
				t.Errorf("unexpected ZIP entries: %#v", names)
			}
		}
		if len(r.MultipartForm.Value) != 0 || len(r.MultipartForm.File) != 1 {
			t.Errorf("unexpected multipart fields: values=%v files=%v", r.MultipartForm.Value, r.MultipartForm.File)
		}
		requestChecked = true
		w.Header().Set("Content-Type", "application/json")
		response := `{"success":true,"sessionId":"abc","report":{"score":85,"status":"Good","issues":[],"recommendations":[],"runtime":{},"docker":{},"security":{},"project":{"path":"."},"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"completed","findingsDetected":false,"findingCount":0,"checks":[{"id":"dockerfile_configuration","status":"completed"},{"id":"owasp_top_10","status":"unsupported"}]},"generatedAt":"2026-10-28T00:00:00.000Z"},"message":"Simulation completed"}`
		var envelope map[string]json.RawMessage
		_ = json.Unmarshal([]byte(response), &envelope)
		var report map[string]json.RawMessage
		_ = json.Unmarshal(envelope["report"], &report)
		report["scan"] = withCompleteChecks(report["scan"])
		report["dependencyAnalysis"], _ = json.Marshal(map[string]any{
			"source": "OSV", "status": "completed", "packageCount": 0,
			"queriedPackageCount": 0, "advisoryCount": 0,
		})
		envelope["report"], _ = json.Marshal(report)
		encoded, _ := json.Marshal(envelope)
		_, _ = w.Write(encoded)
	})
	defer server.Close()

	client := NewClient()
	result, err := client.Scan(context.Background(), project, Config{
		BackendURL: server.URL + "/base",
		APIToken:   "test-api-token",
	})
	if err != nil {
		t.Fatalf("scan project: %v", err)
	}
	if !requestChecked {
		t.Fatal("upload request was not checked")
	}
	var report map[string]json.RawMessage
	if err := json.Unmarshal(result.Report, &report); err != nil {
		t.Fatalf("result report is not JSON: %v", err)
	}
	if string(report["score"]) != "85" || string(report["status"]) != `"Good"` {
		t.Errorf("unexpected report returned: %s", result.Report)
	}
}

func TestClientScanRequiresAPITokenBeforeCreatingArchive(t *testing.T) {
	client := NewClient()
	archiveCalled := false
	client.archiveProject = func(context.Context, string, []string, ArchiveLimits) (string, error) {
		archiveCalled = true
		return "", nil
	}
	_, err := client.Scan(context.Background(), t.TempDir(), Config{BackendURL: "http://localhost"})
	if err == nil || !strings.Contains(err.Error(), APITokenEnv) {
		t.Fatalf("scan error = %v, want API token requirement", err)
	}
	if archiveCalled {
		t.Fatal("archive creation ran without API authentication")
	}
}

func TestClientScanDoesNotFollowAuthenticatedSessionRedirects(t *testing.T) {
	redirectFollowed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/sessions" {
			http.Redirect(w, r, "/capture", http.StatusTemporaryRedirect)
			return
		}
		redirectFollowed = true
	}))
	defer server.Close()

	_, err := NewClient().Scan(context.Background(), t.TempDir(), Config{
		BackendURL: server.URL,
		APIToken:   "test-api-token",
	})
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("scan error = %v, want redirect rejection", err)
	}
	if redirectFollowed {
		t.Fatal("authenticated scanner request followed a redirect")
	}
}

func TestClientScanPassesConfiguredArchiveLimitsAndRejectsOversizedConfiguration(t *testing.T) {
	project := t.TempDir()
	writeProjectFile(t, project, "main.go", "package main")
	server := newSessionTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/sessions" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"sessionId":"test-session","sessionToken":"test-session-capability"}`)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, `{"success":true,"report":{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0}}}`)
	})
	defer server.Close()

	client := NewClient()
	var receivedLimits ArchiveLimits
	client.archiveProject = func(ctx context.Context, projectPath string, excluded []string, limits ArchiveLimits) (string, error) {
		receivedLimits = limits
		return createProjectArchiveWithLimits(ctx, projectPath, excluded, limits)
	}
	_, err := client.Scan(context.Background(), project, Config{
		BackendURL: server.URL,
		APIToken:   "test-api-token",
		ArchiveLimits: ArchiveLimits{
			CompressedBytes: MaxCompressedBytes,
			Entries:         5,
		},
	})
	if err != nil {
		t.Fatalf("scan with lower configured limits: %v", err)
	}
	if receivedLimits.CompressedBytes != MaxCompressedBytes ||
		receivedLimits.ExpandedBytes != MaxExpandedBytes ||
		receivedLimits.Entries != 5 ||
		receivedLimits.IndividualFile != MaxIndividualFile {
		t.Errorf("archive creator received limits %#v", receivedLimits)
	}

	archiveCalled := false
	client.archiveProject = func(context.Context, string, []string, ArchiveLimits) (string, error) {
		archiveCalled = true
		return "", nil
	}
	_, err = client.Scan(context.Background(), project, Config{
		BackendURL: server.URL,
		APIToken:   "test-api-token",
		ArchiveLimits: ArchiveLimits{
			CompressedBytes: MaxCompressedBytes + 1,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "cannot exceed backend upload limits") {
		t.Fatalf("oversized archive configuration error = %v", err)
	}
	if archiveCalled {
		t.Fatal("archive creation ran with limits above backend caps")
	}
}

func TestClientScanReturnsErrorsForBackendAndInvalidResponse(t *testing.T) {
	t.Run("non-success status", func(t *testing.T) {
		server := newSessionTestServer(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "private response contents", http.StatusInternalServerError)
		})
		defer server.Close()

		_, err := NewClient().Scan(context.Background(), t.TempDir(), Config{
			BackendURL: server.URL,
			APIToken:   "test-api-token",
		})
		if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
			t.Fatalf("scan error = %v, want HTTP 500", err)
		}
		if strings.Contains(err.Error(), "private response contents") {
			t.Errorf("scan error exposes backend body: %v", err)
		}
	})

	t.Run("malformed JSON", func(t *testing.T) {
		server := newSessionTestServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"success":`)
		})
		defer server.Close()

		_, err := NewClient().Scan(context.Background(), t.TempDir(), Config{
			BackendURL: server.URL,
			APIToken:   "test-api-token",
		})
		if err == nil || !strings.Contains(err.Error(), "parse scanner response JSON") {
			t.Fatalf("scan error = %v, want malformed JSON error", err)
		}
	})

	t.Run("missing report", func(t *testing.T) {
		server := newSessionTestServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"success":true,"message":"Simulation completed"}`)
		})
		defer server.Close()

		_, err := NewClient().Scan(context.Background(), t.TempDir(), Config{
			BackendURL: server.URL,
			APIToken:   "test-api-token",
		})
		if err == nil || !strings.Contains(err.Error(), "invalid report") {
			t.Fatalf("scan error = %v, want missing report error", err)
		}
	})
}

func TestAssessReportFindingAndCompletionSemantics(t *testing.T) {
	tests := []struct {
		name                 string
		report               string
		wantStatus           string
		wantFindings         bool
		wantCount            int
		wantExplanation      string
		wantError            bool
		wantDependencyStatus string
	}{
		{
			name:            "legacy report without findings is indeterminate",
			report:          `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0}}`,
			wantStatus:      "partial",
			wantExplanation: "legacy report does not include executed check metadata; scan result is indeterminate",
		},
		{
			name:            "legacy report with findings is indeterminate",
			report:          `{"score":80,"status":"Good","issues":[{"severity":"High","title":"Risk indicator"}],"summary":{"critical":0,"high":1,"medium":0,"low":0}}`,
			wantStatus:      "partial",
			wantFindings:    true,
			wantCount:       1,
			wantExplanation: "legacy report does not include executed check metadata; scan result is indeterminate",
		},
		{
			name:       "new completed report with unsupported checks",
			report:     `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"completed","findingsDetected":false,"findingCount":0,"checks":[{"id":"owasp_top_10","status":"unsupported"}]}}`,
			wantStatus: "partial",
		},
		{
			name:       "new passed status remains partial with unsupported coverage",
			report:     `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"partial","findingsDetected":false,"findingCount":0,"checks":[{"id":"image_metadata","status":"passed"}]}}`,
			wantStatus: "partial",
		},
		{
			name:         "new findings status is preserved",
			report:       `{"score":80,"status":"Good","issues":[{"severity":"High","title":"Risk indicator","checkId":"secret_pattern_search"}],"summary":{"critical":0,"high":1,"medium":0,"low":0},"scan":{"status":"partial","findingsDetected":true,"findingCount":1,"checks":[{"id":"secret_pattern_search","status":"findings","findingCount":1}]}}`,
			wantStatus:   "partial",
			wantFindings: true,
			wantCount:    1,
		},
		{
			name:       "new skipped status remains partial",
			report:     `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"partial","findingsDetected":false,"findingCount":0,"checks":[{"id":"runtime_inspection","status":"skipped"}]}}`,
			wantStatus: "partial",
		},
		{
			name:       "new incomplete dependency status is accepted with partial metadata",
			report:     `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"dependencyAnalysis":{"source":"OSV","status":"partial","packageCount":0,"queriedPackageCount":0,"advisoryCount":0},"scan":{"status":"partial","findingsDetected":false,"findingCount":0,"checks":[{"id":"dependency_vulnerability_analysis","status":"incomplete"}]}}`,
			wantStatus: "partial",
		},
		{
			name:                 "passed dependency check with partial metadata is downgraded before aggregate validation",
			report:               `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"dependencyAnalysis":{"source":"OSV","status":"partial","packageCount":0,"queriedPackageCount":0,"advisoryCount":0},"scan":{"status":"partial","findingsDetected":false,"findingCount":0,"checks":[{"id":"dependency_vulnerability_analysis","status":"passed"}]}}`,
			wantStatus:           "partial",
			wantDependencyStatus: "incomplete",
		},
		{
			name:      "unknown check status is rejected",
			report:    `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"partial","findingsDetected":false,"findingCount":0,"checks":[{"id":"image_metadata","status":"looks_good"}]}}`,
			wantError: true,
		},
		{
			name:      "unimplemented OWASP check cannot claim completed",
			report:    `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"completed","findingsDetected":false,"findingCount":0,"checks":[{"id":"owasp_top_10","status":"completed"}]}}`,
			wantError: true,
		},
		{
			name:      "findings status cannot omit its attributed findings",
			report:    `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"partial","findingsDetected":false,"findingCount":0,"checks":[{"id":"secret_pattern_search","status":"findings"}]}}`,
			wantError: true,
		},
		{
			name:      "modern completed scan contradicting unsupported checks is rejected",
			report:    `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"completed","findingsDetected":false,"findingCount":0,"checks":[{"id":"owasp_top_10","status":"unsupported"}]}}`,
			wantError: true,
		},
		{
			name:      "completed scan contradicting failed check is rejected",
			report:    `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"completed","findingsDetected":false,"findingCount":0,"checks":[{"id":"image_metadata","status":"failed"}]}}`,
			wantError: true,
		},
		{
			name:       "legacy completed scan with unsupported checks is downgraded",
			report:     `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"completed","findingsDetected":false,"findingCount":0,"checks":[{"id":"owasp_top_10","status":"unsupported"}]}}`,
			wantStatus: "partial",
		},
		{
			name:            "legacy backend with unsupported dependency analysis is indeterminate",
			report:          `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"completed","findingsDetected":false,"findingCount":0,"checks":[{"id":"dependency_vulnerability_analysis","status":"unsupported"}]}}`,
			wantStatus:      "partial",
			wantExplanation: "one or more checks are failed, skipped, unsupported, or incomplete; no findings in the performed checks does not establish that the application is secure",
		},
		{
			name:       "completed dependency analysis has consistent manifest metadata",
			report:     `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"dependencyAnalysis":{"source":"OSV","status":"completed","packageCount":2,"queriedPackageCount":2,"advisoryCount":0},"scan":{"status":"completed","findingsDetected":false,"findingCount":0,"checks":[{"id":"dependency_vulnerability_analysis","status":"completed"}]}}`,
			wantStatus: "partial",
		},
		{
			name:         "dependency advisory finding is validated and retained",
			report:       `{"score":90,"status":"Excellent","issues":[{"severity":"High","title":"Dependency vulnerability: library-a (GHSA-test-1234)","dependency":{"ecosystem":"npm","package":"library-a","installedVersion":"1.2.3","relationship":"direct","advisoryId":"GHSA-test-1234","fixedVersion":"2.0.0","advisoryModified":"2025-01-02T03:04:05Z"}}],"summary":{"critical":0,"high":1,"medium":0,"low":0},"dependencyAnalysis":{"source":"OSV","status":"completed","packageCount":1,"queriedPackageCount":1,"advisoryCount":1},"scan":{"status":"completed","findingsDetected":true,"findingCount":1,"checks":[{"id":"dependency_vulnerability_analysis","status":"completed"}]}}`,
			wantStatus:   "partial",
			wantFindings: true,
			wantCount:    1,
		},
		{
			name:      "dependency advisory count must match findings",
			report:    `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"dependencyAnalysis":{"source":"OSV","status":"completed","packageCount":1,"queriedPackageCount":1,"advisoryCount":1},"scan":{"status":"completed","findingsDetected":false,"findingCount":0,"checks":[{"id":"dependency_vulnerability_analysis","status":"completed"}]}}`,
			wantError: true,
		},
		{
			name:         "unknown advisory severity remains reportable",
			report:       `{"score":100,"status":"Excellent","issues":[{"severity":"Unknown","title":"Dependency vulnerability: library-a (GHSA-test-1234)","dependency":{"ecosystem":"npm","package":"library-a","installedVersion":"1.2.3","relationship":"transitive","advisoryId":"GHSA-test-1234"}}],"summary":{"critical":0,"high":0,"medium":0,"low":0,"unknown":1},"dependencyAnalysis":{"source":"OSV","status":"completed","packageCount":1,"queriedPackageCount":1,"advisoryCount":1},"scan":{"status":"completed","findingsDetected":true,"findingCount":1,"checks":[{"id":"dependency_vulnerability_analysis","status":"completed"}]}}`,
			wantStatus:   "partial",
			wantFindings: true,
			wantCount:    1,
		},
		{
			name:      "completed dependency analysis cannot omit source metadata",
			report:    `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"completed","findingsDetected":false,"findingCount":0,"checks":[{"id":"dependency_vulnerability_analysis","status":"completed"}]}}`,
			wantError: true,
		},
		{
			name:       "partial analyzer failure",
			report:     `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"partial","findingsDetected":false,"findingCount":0,"checks":[{"id":"image_metadata","status":"failed"}]}}`,
			wantStatus: "partial",
		},
		{
			name:      "missing findings array",
			report:    `{"score":100,"status":"Excellent","summary":{"critical":0,"high":0,"medium":0,"low":0}}`,
			wantError: true,
		},
		{
			name:      "incomplete summary",
			report:    `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0}}`,
			wantError: true,
		},
		{
			name:      "legacy report missing summary metadata",
			report:    `{"score":100,"status":"Excellent","issues":[]}`,
			wantError: true,
		},
		{
			name:      "legacy report with contradictory summary",
			report:    `{"score":80,"status":"Good","issues":[{"severity":"High","title":"Risk indicator"}],"summary":{"critical":0,"high":0,"medium":0,"low":0}}`,
			wantError: true,
		},
		{
			name:      "contradictory finding metadata",
			report:    `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"completed","findingsDetected":true,"findingCount":1,"checks":[]}}`,
			wantError: true,
		},
		{
			name:      "completed report with empty checks",
			report:    `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"completed","findingsDetected":false,"findingCount":0,"checks":[]}}`,
			wantError: true,
		},
		{
			name:      "missing checks",
			report:    `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"completed","findingsDetected":false,"findingCount":0}}`,
			wantError: true,
		},
		{
			name:      "missing expected check identifier",
			report:    `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"completed","findingsDetected":false,"findingCount":0,"checks":[{"id":"image_metadata","status":"completed"}]}}`,
			wantError: true,
		},
		{
			name:      "duplicate check identifiers",
			report:    `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"completed","findingsDetected":false,"findingCount":0,"checks":[{"id":"image_metadata","status":"completed"},{"id":"image_metadata","status":"completed"}]}}`,
			wantError: true,
		},
		{
			name:      "implemented check incorrectly marked not performed",
			report:    `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"completed","findingsDetected":false,"findingCount":0,"checks":[{"id":"secret_pattern_search","status":"not_performed"}]}}`,
			wantError: true,
		},
		{
			name:      "partial result with no failed check",
			report:    `{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"partial","findingsDetected":false,"findingCount":0,"checks":[]}}`,
			wantError: true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			report := withCompleteChecks(json.RawMessage(testCase.report))
			switch testCase.name {
			case "legacy report without findings is indeterminate",
				"legacy report with findings is indeterminate",
				"legacy report missing summary metadata",
				"legacy report with contradictory summary":
				report = json.RawMessage(testCase.report)
			case "contradictory finding metadata", "completed report with empty checks",
				"missing checks", "missing expected check identifier", "duplicate check identifiers",
				"implemented check incorrectly marked not performed", "partial result with no failed check":
				report = json.RawMessage(testCase.report)
			case "legacy backend with unsupported dependency analysis is indeterminate",
				"completed dependency analysis has consistent manifest metadata",
				"dependency advisory finding is validated and retained",
				"dependency advisory count must match findings",
				"unknown advisory severity remains reportable":
				report = withCompleteChecks(json.RawMessage(testCase.report))
			case "completed dependency analysis cannot omit source metadata":
				report = withCompleteChecks(json.RawMessage(testCase.report))
				var value map[string]any
				if err := json.Unmarshal(report, &value); err == nil {
					delete(value, "dependencyAnalysis")
					if updated, err := json.Marshal(value); err == nil {
						report = updated
					}
				}
			case "modern completed scan contradicting unsupported checks is rejected",
				"completed scan contradicting failed check is rejected",
				"legacy completed scan with unsupported checks is downgraded":
				var value map[string]any
				if err := json.Unmarshal(report, &value); err == nil {
					scan := value["scan"].(map[string]any)
					scan["status"] = "completed"
					if testCase.name == "modern completed scan contradicting unsupported checks is rejected" {
						for _, rawCheck := range scan["checks"].([]any) {
							check := rawCheck.(map[string]any)
							if check["status"] == "completed" {
								check["status"] = "passed"
							}
						}
					}
					if updated, err := json.Marshal(value); err == nil {
						report = updated
					}
				}
			}
			outcome, err := AssessReport(report)
			if (err != nil) != testCase.wantError {
				t.Fatalf("AssessReport error = %v, wantError %t", err, testCase.wantError)
			}
			if err != nil {
				return
			}
			if outcome.Status != testCase.wantStatus ||
				outcome.FindingsDetected != testCase.wantFindings ||
				outcome.FindingCount != testCase.wantCount ||
				testCase.wantExplanation != "" && outcome.Explanation != testCase.wantExplanation {
				t.Errorf("AssessReport outcome = %#v", outcome)
			}
			if testCase.wantDependencyStatus != "" {
				foundDependencyCheck := false
				for _, check := range outcome.Checks {
					if check.ID == "dependency_vulnerability_analysis" {
						foundDependencyCheck = true
						if check.Status != testCase.wantDependencyStatus {
							t.Errorf("dependency check status = %q, want %q", check.Status, testCase.wantDependencyStatus)
						}
					}
				}
				if !foundDependencyCheck {
					t.Error("dependency check missing from outcome")
				}
			}
		})
	}
}

func TestAssessReportMissingCoverageExplanationIsIndeterminate(t *testing.T) {
	raw := withCompleteChecks(json.RawMessage(`{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0},"scan":{"status":"completed","findingsDetected":false,"findingCount":0,"checks":[{"id":"image_metadata","status":"completed"}]}}`))
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	scan := report["scan"].(map[string]any)
	checks := scan["checks"].([]any)
	delete(checks[0].(map[string]any), "scope")
	malformed, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}

	outcome, err := AssessReport(malformed)
	if err != nil {
		t.Fatalf("AssessReport returned error: %v", err)
	}
	if outcome.Status != "partial" ||
		outcome.Explanation != "report is missing per-check scope, explanation, or finding attribution metadata; scan result is indeterminate" {
		t.Fatalf("AssessReport outcome = %#v, want indeterminate partial result", outcome)
	}
}

func TestClientScanRemovesArchiveOnSuccessAndBackendFailure(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := newSessionTestServer(func(w http.ResponseWriter, _ *http.Request) {
				if status == http.StatusOK {
					_, _ = io.WriteString(w, `{"success":true,"report":{"score":100,"status":"Excellent","issues":[],"summary":{"critical":0,"high":0,"medium":0,"low":0}}}`)
					return
				}
				http.Error(w, "backend failure", status)
			})
			defer server.Close()

			project := t.TempDir()
			writeProjectFile(t, project, "main.go", "package main")
			client := NewClient()
			var archivePath string
			client.archiveProject = func(ctx context.Context, project string, excluded []string, _ ArchiveLimits) (string, error) {
				path, err := createProjectArchive(ctx, project, excluded)
				archivePath = path
				return path, err
			}

			_, err := client.Scan(context.Background(), project, Config{
				BackendURL: server.URL,
				APIToken:   "test-api-token",
			})
			if status == http.StatusOK && err != nil {
				t.Fatalf("scan project: %v", err)
			}
			if status != http.StatusOK && err == nil {
				t.Fatal("scan succeeded despite backend failure")
			}
			if _, statErr := os.Stat(archivePath); !errors.Is(statErr, os.ErrNotExist) {
				t.Errorf("temporary archive still exists after HTTP %d: %v", status, statErr)
			}
		})
	}
}

func TestClientScanHonorsTimeoutAndCancellationAndCleansArchive(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		configure func(*testing.T, *httptest.Server) (context.Context, Config)
		wantErr   error
		wantText  string
	}{
		{
			name: "timeout",
			configure: func(_ *testing.T, server *httptest.Server) (context.Context, Config) {
				return context.Background(), Config{
					BackendURL: server.URL,
					APIToken:   "test-api-token",
					Timeout:    30 * time.Millisecond,
				}
			},
			wantErr:  context.DeadlineExceeded,
			wantText: "did not complete",
		},
		{
			name: "cancellation",
			configure: func(t *testing.T, server *httptest.Server) (context.Context, Config) {
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				return ctx, Config{BackendURL: server.URL, APIToken: "test-api-token"}
			},
			wantErr:  context.Canceled,
			wantText: "did not complete",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			requestStarted := make(chan struct{})
			releaseHandler := make(chan struct{})
			var startOnce sync.Once
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseHandler) }) }
			server := newSessionTestServer(func(_ http.ResponseWriter, r *http.Request) {
				startOnce.Do(func() { close(requestStarted) })
				if r.URL.Path == "/api/sessions" {
					return
				}
				select {
				case <-r.Context().Done():
				case <-releaseHandler:
				}
			})
			defer func() {
				release()
				server.Close()
			}()

			ctx, config := testCase.configure(t, server)
			project := t.TempDir()
			writeProjectFile(t, project, "main.go", "package main")
			var archivePath string
			client := NewClient()
			client.archiveProject = func(ctx context.Context, project string, excluded []string, _ ArchiveLimits) (string, error) {
				path, err := createProjectArchive(ctx, project, excluded)
				archivePath = path
				return path, err
			}
			cancel := func() {}
			if testCase.name == "cancellation" {
				ctx, cancel = context.WithCancel(ctx)
			}
			t.Cleanup(cancel)

			scanResult := make(chan error, 1)
			go func() {
				_, err := client.Scan(ctx, project, config)
				scanResult <- err
			}()
			select {
			case <-requestStarted:
			case <-time.After(2 * time.Second):
				t.Fatal("request did not reach test server")
			}
			if testCase.name == "cancellation" {
				cancel()
			}

			err := <-scanResult
			release()
			if err == nil || (!errors.Is(err, testCase.wantErr) && !strings.Contains(err.Error(), testCase.wantText)) {
				t.Fatalf("scan error = %v, want %v", err, testCase.wantErr)
			}
			if _, statErr := os.Stat(archivePath); !errors.Is(statErr, os.ErrNotExist) {
				t.Errorf("temporary archive still exists after scan: %v", statErr)
			}
		})
	}
}

func TestUploadEndpointRequiresConfigurableHTTPBaseURL(t *testing.T) {
	if _, err := uploadEndpoint(""); err == nil || !strings.Contains(err.Error(), BackendURLEnv) {
		t.Fatalf("empty backend URL error = %v, want %s requirement", err, BackendURLEnv)
	}
	for _, backendURL := range []string{
		"file:///tmp/backend",
		"https://user:password@example.com",
		"https://example.com?token=secret",
	} {
		if _, err := uploadEndpoint(backendURL); err == nil {
			t.Errorf("uploadEndpoint(%q) succeeded, want invalid URL error", backendURL)
		}
	}
}

func TestUploadEndpointRequiresHTTPSOutsideLoopback(t *testing.T) {
	for _, backendURL := range []string{
		"http://localhost:5000",
		"http://LOCALHOST:5000",
		"http://127.0.0.1:5000",
		"http://[::1]:5000",
		"https://example.com",
	} {
		if endpoint, err := uploadEndpoint(backendURL); err != nil {
			t.Errorf("uploadEndpoint(%q) error = %v, want success", backendURL, err)
		} else if !strings.HasSuffix(endpoint, "/api/upload") {
			t.Errorf("uploadEndpoint(%q) = %q, want upload endpoint suffix", backendURL, endpoint)
		}
	}

	for _, backendURL := range []string{
		"http://example.com",
		"http://192.0.2.1:5000",
		"http://[2001:db8::1]:5000",
	} {
		if _, err := uploadEndpoint(backendURL); err == nil ||
			!strings.Contains(err.Error(), "must use HTTPS") {
			t.Errorf("uploadEndpoint(%q) error = %v, want HTTPS requirement", backendURL, err)
		}
	}
}

func writeProjectFile(t *testing.T, root, relative, content string) string {
	t.Helper()
	filePath := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
		t.Fatalf("create project directory: %v", err)
	}
	if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
		t.Fatalf("write project file: %v", err)
	}
	return filePath
}
