package scanner

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const (
	BackendURLEnv       = "LUMINICENT_BACKEND_URL"
	APITokenEnv         = "LUMINICENT_API_TOKEN"
	MaxArchivePathDepth = 32
	DefaultTimeout      = 10 * time.Minute
	MaxCompressedBytes  = 100 << 20
	MaxExpandedBytes    = 1 << 30
	MaxArchiveEntries   = 10_000
	MaxIndividualFile   = 100 << 20
	maxResponseSize     = 10 << 20
)

type ArchiveLimits struct {
	CompressedBytes int64
	ExpandedBytes   int64
	Entries         int
	IndividualFile  int64
}

var errCompressedArchiveLimit = errors.New("project archive exceeds the configured compressed size limit")

type Config struct {
	BackendURL    string
	APIToken      string
	Timeout       time.Duration
	ExcludePaths  []string
	ArchiveLimits ArchiveLimits
}

type Result struct {
	Report json.RawMessage
}

type ReportOutcome struct {
	Status           string
	FindingsDetected bool
	FindingCount     int
	Explanation      string
	Coverage         CoverageCounts
	Checks           []ReportCheck
}

type CoverageCounts struct {
	Passed      int
	Findings    int
	Failed      int
	Skipped     int
	Unsupported int
	Incomplete  int
}

type ReportCheck struct {
	ID          string
	Name        string
	Status      string
	Scope       string
	Explanation string
}

type Scanner interface {
	Scan(ctx context.Context, projectPath string, config Config) (Result, error)
}

type Client struct {
	archiveProject func(context.Context, string, []string, ArchiveLimits) (string, error)
}

func NewClient() *Client {
	return &Client{archiveProject: createProjectArchiveWithLimits}
}

func (c *Client) Scan(ctx context.Context, projectPath string, config Config) (result Result, resultErr error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("scan context cannot be nil")
	}

	endpoint, err := uploadEndpoint(config.BackendURL)
	if err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(config.APIToken) == "" {
		return Result{}, fmt.Errorf("%s is required to run a scan", APITokenEnv)
	}
	archiveLimits, err := resolveArchiveLimits(config.ArchiveLimits)
	if err != nil {
		return Result{}, err
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	scanContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	createArchive := c.archiveProject
	if createArchive == nil {
		createArchive = createProjectArchiveWithLimits
	}
	archivePath, err := createArchive(scanContext, projectPath, config.ExcludePaths, archiveLimits)
	if err != nil {
		if archivePath != "" {
			if cleanupErr := os.Remove(archivePath); cleanupErr != nil && !errors.Is(cleanupErr, os.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("remove incomplete project archive: %w", cleanupErr))
			}
		}
		return Result{}, fmt.Errorf("create project archive: %w", err)
	}
	defer func() {
		if err := os.Remove(archivePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove temporary project archive: %w", err))
		}
	}()

	archiveFile, err := os.Open(archivePath)
	if err != nil {
		return Result{}, fmt.Errorf("open temporary project archive: %w", err)
	}
	defer func() {
		if err := archiveFile.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close temporary project archive: %w", err))
		}
	}()

	pipeReader, pipeWriter := io.Pipe()
	form := multipart.NewWriter(pipeWriter)
	writeResult := make(chan error, 1)

	go func() {
		partHeader := make(textproto.MIMEHeader)
		partHeader["Content-Disposition"] = []string{`form-data; name="file"; filename="project.zip"`}
		partHeader["Content-Type"] = []string{"application/zip"}
		part, writeErr := form.CreatePart(partHeader)
		if writeErr == nil {
			_, writeErr = io.Copy(part, contextReader{ctx: scanContext, reader: archiveFile})
		}
		if writeErr == nil {
			writeErr = form.Close()
		}
		if writeErr != nil {
			_ = pipeWriter.CloseWithError(writeErr)
		} else {
			_ = pipeWriter.Close()
		}
		writeResult <- writeErr
	}()

	session, err := createSession(scanContext, strings.TrimSuffix(endpoint, "/upload")+"/sessions", config.APIToken)
	if err != nil {
		_ = pipeReader.CloseWithError(err)
		<-writeResult
		return Result{}, err
	}
	defer func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if cleanupErr := cleanupSession(
			cleanupContext,
			strings.TrimSuffix(endpoint, "/upload")+"/cleanup",
			config.APIToken,
			session,
		); cleanupErr != nil {
			resultErr = errors.Join(resultErr, cleanupErr)
		}
	}()

	request, err := http.NewRequestWithContext(scanContext, http.MethodPost, endpoint, pipeReader)
	if err != nil {
		_ = pipeReader.CloseWithError(err)
		<-writeResult
		return Result{}, fmt.Errorf("create scanner request: %w", err)
	}
	request.Header.Set("Content-Type", form.FormDataContentType())
	request.Header.Set("Authorization", "Bearer "+config.APIToken)
	request.Header.Set("X-Luminicent-Session-Id", session.SessionID)
	request.Header.Set("X-Luminicent-Session-Token", session.SessionToken)

	response, requestErr := newScannerHTTPClient(timeout).Do(request)
	if requestErr != nil {
		_ = pipeReader.CloseWithError(requestErr)
		<-writeResult
		if scanContext.Err() != nil {
			return Result{}, fmt.Errorf("scanner request did not complete: %w", scanContext.Err())
		}
		return Result{}, fmt.Errorf("send scanner request: %w", requestErr)
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_ = pipeReader.CloseWithError(fmt.Errorf("backend rejected project upload"))
		<-writeResult
		return Result{}, fmt.Errorf("scanner backend returned HTTP %d", response.StatusCode)
	}
	writeErr := <-writeResult
	if writeErr != nil {
		return Result{}, fmt.Errorf("upload project archive: %w", writeErr)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if err != nil {
		return Result{}, fmt.Errorf("read scanner response: %w", err)
	}
	if len(body) > maxResponseSize {
		return Result{}, fmt.Errorf("scanner response exceeds %d bytes", maxResponseSize)
	}

	var envelope struct {
		Success bool            `json:"success"`
		Report  json.RawMessage `json:"report"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return Result{}, fmt.Errorf("parse scanner response JSON: %w", err)
	}
	if !envelope.Success {
		return Result{}, fmt.Errorf("scanner backend reported that the scan did not succeed")
	}
	if _, err := AssessReport(envelope.Report); err != nil {
		return Result{}, fmt.Errorf("scanner response contains an invalid report: %w", err)
	}

	return Result{Report: envelope.Report}, nil
}

// AssessReport validates the current scan contract and the supported legacy report shape.
func AssessReport(raw json.RawMessage) (ReportOutcome, error) {
	var report map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &report) != nil || report == nil {
		return ReportOutcome{}, fmt.Errorf("report must be a JSON object")
	}

	var score float64
	if err := json.Unmarshal(report["score"], &score); err != nil || score < 0 || score > 100 {
		return ReportOutcome{}, fmt.Errorf("report is missing a valid score")
	}
	var quality string
	if err := json.Unmarshal(report["status"], &quality); err != nil || strings.TrimSpace(quality) == "" {
		return ReportOutcome{}, fmt.Errorf("report is missing a valid quality status")
	}

	var issues []json.RawMessage
	if err := json.Unmarshal(report["issues"], &issues); err != nil || issues == nil {
		return ReportOutcome{}, fmt.Errorf("report is missing a valid issues array")
	}
	issueFindingCounts := make(map[string]int)
	issuesMissingCheckID := false
	for index, rawIssue := range issues {
		var issue map[string]json.RawMessage
		if err := json.Unmarshal(rawIssue, &issue); err != nil || issue == nil {
			return ReportOutcome{}, fmt.Errorf("report issue %d is invalid", index)
		}
		var severity, title string
		if json.Unmarshal(issue["severity"], &severity) != nil ||
			json.Unmarshal(issue["title"], &title) != nil ||
			strings.TrimSpace(severity) == "" || strings.TrimSpace(title) == "" {
			return ReportOutcome{}, fmt.Errorf("report issue %d is missing severity or title", index)
		}
		if rawCheckID, exists := issue["checkId"]; exists {
			var checkID string
			if json.Unmarshal(rawCheckID, &checkID) != nil || strings.TrimSpace(checkID) == "" {
				return ReportOutcome{}, fmt.Errorf("report issue %d has an invalid check id", index)
			}
			issueFindingCounts[checkID]++
		} else {
			issuesMissingCheckID = true
		}
	}

	var scanRaw json.RawMessage
	if rawScan, exists := report["scan"]; exists {
		scanRaw = rawScan
	}
	if len(scanRaw) == 0 {
		if err := validateLegacySummary(report["summary"], issues); err != nil {
			return ReportOutcome{}, err
		}
		return ReportOutcome{
			Status:           "partial",
			FindingsDetected: len(issues) > 0,
			FindingCount:     len(issues),
			Explanation:      "legacy report does not include executed check metadata; scan result is indeterminate",
		}, nil
	}

	var scan struct {
		Status           string `json:"status"`
		FindingsDetected *bool  `json:"findingsDetected"`
		FindingCount     *int   `json:"findingCount"`
		Checks           []struct {
			ID           string `json:"id"`
			Name         string `json:"name"`
			Status       string `json:"status"`
			Scope        string `json:"scope"`
			Explanation  string `json:"explanation"`
			FindingCount *int   `json:"findingCount"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(scanRaw, &scan); err != nil ||
		scan.FindingsDetected == nil || scan.FindingCount == nil || scan.Checks == nil {
		return ReportOutcome{}, fmt.Errorf("report scan metadata is incomplete")
	}
	var dependencyAnalysis *struct {
		Source              string `json:"source"`
		Status              string `json:"status"`
		PackageCount        *int   `json:"packageCount"`
		QueriedPackageCount *int   `json:"queriedPackageCount"`
		AdvisoryCount       *int   `json:"advisoryCount"`
	}
	if rawAnalysis, exists := report["dependencyAnalysis"]; exists {
		dependencyAnalysis = &struct {
			Source              string `json:"source"`
			Status              string `json:"status"`
			PackageCount        *int   `json:"packageCount"`
			QueriedPackageCount *int   `json:"queriedPackageCount"`
			AdvisoryCount       *int   `json:"advisoryCount"`
		}{}
		if err := json.Unmarshal(rawAnalysis, &dependencyAnalysis); err != nil {
			return ReportOutcome{}, fmt.Errorf("report dependency analysis metadata is invalid")
		}
	}
	if scan.Status != "completed" && scan.Status != "partial" {
		return ReportOutcome{}, fmt.Errorf("report scan status is not completed")
	}
	if len(scan.Checks) == 0 {
		return ReportOutcome{}, fmt.Errorf("report scan contains no checks")
	}
	incompleteCoverage := false
	coverageMetadataMissing := issuesMissingCheckID
	legacyCheckStatuses := false
	checkIDs := make(map[string]struct{}, len(scan.Checks))
	checkStatuses := make(map[string]string, len(scan.Checks))
	checkFindingCounts := make(map[string]int, len(scan.Checks))
	var coverage CoverageCounts
	checkOutcomes := make([]ReportCheck, 0, len(scan.Checks))
	expectedCheckIDs := map[string]bool{
		"dockerfile_presence":                 false,
		"dockerfile_configuration":            false,
		"dockerignore_configuration":          false,
		"environment_configuration":           false,
		"image_metadata":                      false,
		"runtime_inspection":                  false,
		"secret_pattern_search":               false,
		"insecure_transport_configuration":    false,
		"dangerous_application_configuration": false,
		"project_structure":                   false,
		"owasp_top_10":                        true,
		"dynamic_vulnerability_testing":       true,
		"dependency_vulnerability_analysis":   false,
		"exploit_verification":                true,
	}
	unsupportedCheckIDs := map[string]bool{
		"owasp_top_10":                      true,
		"dynamic_vulnerability_testing":     true,
		"dependency_vulnerability_analysis": true,
		"exploit_verification":              true,
	}
	unimplementedCheckIDs := map[string]bool{
		"owasp_top_10":                  true,
		"dynamic_vulnerability_testing": true,
		"exploit_verification":          true,
	}
	notPerformedAllowed := map[string]bool{
		"dockerfile_configuration":   true,
		"dockerignore_configuration": true,
		"runtime_inspection":         true,
	}
	optionalCheckIDs := map[string]bool{
		"insecure_transport_configuration":    true,
		"dangerous_application_configuration": true,
	}
	for index, check := range scan.Checks {
		if strings.TrimSpace(check.ID) == "" {
			return ReportOutcome{}, fmt.Errorf("report check %d is missing an id", index)
		}
		isUnsupportedCheck, exists := expectedCheckIDs[check.ID]
		if !exists {
			return ReportOutcome{}, fmt.Errorf("report check %q is unsupported by this CLI", check.ID)
		}
		if _, exists := checkIDs[check.ID]; exists {
			return ReportOutcome{}, fmt.Errorf("report contains duplicate check ids")
		}
		checkIDs[check.ID] = struct{}{}
		if unimplementedCheckIDs[check.ID] && check.Status != "unsupported" {
			return ReportOutcome{}, fmt.Errorf("report check %q must be marked unsupported", check.ID)
		}
		switch check.Status {
		case "passed", "findings", "completed", "failed", "skipped", "not_performed", "unsupported", "incomplete":
			if check.Status == "completed" || check.Status == "not_performed" {
				legacyCheckStatuses = true
			}
			if check.Status == "unsupported" && !unsupportedCheckIDs[check.ID] ||
				check.Status != "unsupported" && check.Status != "completed" &&
					check.Status != "not_performed" && isUnsupportedCheck {
				return ReportOutcome{}, fmt.Errorf("report check %q has an inconsistent status", check.ID)
			}
			if (check.Status == "not_performed" || check.Status == "skipped") &&
				!notPerformedAllowed[check.ID] {
				return ReportOutcome{}, fmt.Errorf("report check %q was unexpectedly not performed", check.ID)
			}
			status := check.Status
			if status == "completed" {
				hasFindings := issueFindingCounts[check.ID] > 0 ||
					check.FindingCount != nil && *check.FindingCount > 0
				if check.ID == "dependency_vulnerability_analysis" &&
					dependencyAnalysis != nil && dependencyAnalysis.AdvisoryCount != nil &&
					*dependencyAnalysis.AdvisoryCount > 0 {
					hasFindings = true
				}
				if hasFindings {
					status = "findings"
				} else {
					status = "passed"
				}
			} else if status == "not_performed" {
				status = "skipped"
			}
			if check.ID == "dependency_vulnerability_analysis" &&
				dependencyAnalysis != nil && dependencyAnalysis.Status == "partial" &&
				(status == "passed" || status == "findings") {
				status = "incomplete"
			}
			checkStatuses[check.ID] = status
			if strings.TrimSpace(check.Name) == "" ||
				strings.TrimSpace(check.Scope) == "" ||
				strings.TrimSpace(check.Explanation) == "" {
				coverageMetadataMissing = true
			}
			if check.FindingCount != nil {
				if *check.FindingCount < 0 {
					return ReportOutcome{}, fmt.Errorf("report check %q has an invalid finding count", check.ID)
				}
				checkFindingCounts[check.ID] = *check.FindingCount
			}
			if status == "findings" && check.FindingCount != nil && *check.FindingCount == 0 ||
				status == "passed" && check.FindingCount != nil && *check.FindingCount != 0 {
				return ReportOutcome{}, fmt.Errorf("report check %q has a contradictory finding count", check.ID)
			}
			if status == "findings" && issueFindingCounts[check.ID] == 0 &&
				(check.FindingCount == nil || *check.FindingCount == 0) && !issuesMissingCheckID ||
				status == "passed" && issueFindingCounts[check.ID] > 0 {
				return ReportOutcome{}, fmt.Errorf("report check %q status contradicts its attributed findings", check.ID)
			}
			switch status {
			case "passed":
				coverage.Passed++
			case "findings":
				coverage.Findings++
			case "failed":
				coverage.Failed++
				incompleteCoverage = true
			case "skipped":
				coverage.Skipped++
				incompleteCoverage = true
			case "unsupported":
				coverage.Unsupported++
				incompleteCoverage = true
			case "incomplete":
				coverage.Incomplete++
				incompleteCoverage = true
			}
			checkOutcomes = append(checkOutcomes, ReportCheck{
				ID:          check.ID,
				Name:        check.Name,
				Status:      status,
				Scope:       check.Scope,
				Explanation: check.Explanation,
			})
			if (status == "passed" || status == "findings") &&
				!issuesMissingCheckID {
				if _, exists := checkFindingCounts[check.ID]; exists &&
					checkFindingCounts[check.ID] != issueFindingCounts[check.ID] {
					return ReportOutcome{}, fmt.Errorf("report check %q finding count contradicts its issues", check.ID)
				}
			}
		default:
			return ReportOutcome{}, fmt.Errorf("report check %q has an invalid status", check.ID)
		}
	}
	for checkID := range expectedCheckIDs {
		if _, exists := checkIDs[checkID]; !exists {
			if optionalCheckIDs[checkID] {
				coverageMetadataMissing = true
				continue
			}
			return ReportOutcome{}, fmt.Errorf("report is missing expected check %q", checkID)
		}
	}
	for checkID := range issueFindingCounts {
		if _, supported := expectedCheckIDs[checkID]; !supported {
			return ReportOutcome{}, fmt.Errorf("report contains an issue for an unsupported check")
		}
	}
	dependencyStatus := checkStatuses["dependency_vulnerability_analysis"]
	dependencyUnsupported := dependencyStatus == "unsupported"
	dependencyIssueCount, err := validateDependencyFindings(issues)
	if err != nil {
		return ReportOutcome{}, err
	}
	if dependencyStatus == "completed" || dependencyStatus == "passed" ||
		dependencyStatus == "findings" || dependencyStatus == "incomplete" {
		analysis := dependencyAnalysis
		if analysis == nil || analysis.Source != "OSV" ||
			(analysis.Status != "completed" && analysis.Status != "partial") ||
			analysis.PackageCount == nil || *analysis.PackageCount < 0 ||
			analysis.QueriedPackageCount == nil ||
			*analysis.QueriedPackageCount != *analysis.PackageCount ||
			analysis.AdvisoryCount == nil || *analysis.AdvisoryCount < 0 ||
			*analysis.AdvisoryCount != dependencyIssueCount ||
			dependencyStatus == "passed" && dependencyIssueCount != 0 ||
			dependencyStatus == "findings" && dependencyIssueCount == 0 {
			return ReportOutcome{}, fmt.Errorf("completed dependency analysis metadata is incomplete or inconsistent")
		}
		if analysis.Status == "partial" {
			if dependencyStatus != "incomplete" {
				incompleteCoverage = true
				coverage.Incomplete++
			}
		}
	}
	findingsDetected := len(issues) > 0
	if *scan.FindingsDetected != findingsDetected || *scan.FindingCount != len(issues) {
		return ReportOutcome{}, fmt.Errorf("report finding metadata contradicts its issues")
	}
	if err := validateLegacySummary(report["summary"], issues); err != nil {
		return ReportOutcome{}, err
	}
	wantPartial := incompleteCoverage || coverageMetadataMissing
	if (scan.Status == "partial") != wantPartial {
		legacyCompletedPartial := scan.Status == "completed" && legacyCheckStatuses &&
			coverage.Failed == 0 &&
			(coverage.Unsupported > 0 || coverage.Skipped > 0 || coverage.Incomplete > 0)
		if !legacyCompletedPartial {
			return ReportOutcome{}, fmt.Errorf("report scan status contradicts its check results")
		}
	}

	outcomeStatus := scan.Status
	explanation := ""
	if incompleteCoverage || coverageMetadataMissing {
		outcomeStatus = "partial"
		explanation = "one or more checks are failed, skipped, unsupported, or incomplete; no findings in the performed checks does not establish that the application is secure"
		if coverageMetadataMissing {
			explanation = "report is missing per-check scope, explanation, or finding attribution metadata; scan result is indeterminate"
		}
	} else if dependencyUnsupported {
		outcomeStatus = "partial"
		explanation = "dependency vulnerability analysis is unsupported or unavailable; scan result is indeterminate"
	}
	return ReportOutcome{
		Status:           outcomeStatus,
		FindingsDetected: findingsDetected,
		FindingCount:     len(issues),
		Explanation:      explanation,
		Coverage:         coverage,
		Checks:           checkOutcomes,
	}, nil
}

func validateDependencyFindings(issues []json.RawMessage) (int, error) {
	count := 0
	for _, rawIssue := range issues {
		var issue struct {
			Dependency *struct {
				Ecosystem        string `json:"ecosystem"`
				Package          string `json:"package"`
				InstalledVersion string `json:"installedVersion"`
				Relationship     string `json:"relationship"`
				AdvisoryID       string `json:"advisoryId"`
				FixedVersion     string `json:"fixedVersion"`
				AdvisoryModified string `json:"advisoryModified"`
			} `json:"dependency"`
		}
		if err := json.Unmarshal(rawIssue, &issue); err != nil {
			return 0, fmt.Errorf("report contains an invalid dependency finding")
		}
		if issue.Dependency == nil {
			continue
		}
		dependency := issue.Dependency
		if dependency.Ecosystem != "npm" || strings.TrimSpace(dependency.Package) == "" ||
			strings.TrimSpace(dependency.InstalledVersion) == "" ||
			(dependency.Relationship != "direct" && dependency.Relationship != "transitive") ||
			strings.TrimSpace(dependency.AdvisoryID) == "" {
			return 0, fmt.Errorf("report contains incomplete dependency finding metadata")
		}
		if dependency.AdvisoryModified != "" {
			if _, err := time.Parse(time.RFC3339Nano, dependency.AdvisoryModified); err != nil {
				return 0, fmt.Errorf("report contains an invalid advisory modification time")
			}
		}
		count++
	}
	return count, nil
}

func validateLegacySummary(raw json.RawMessage, issues []json.RawMessage) error {
	var summary map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &summary) != nil || summary == nil {
		return fmt.Errorf("report is missing a valid findings summary")
	}
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
	for _, rawIssue := range issues {
		var issue struct {
			Severity string `json:"severity"`
		}
		if err := json.Unmarshal(rawIssue, &issue); err != nil {
			return fmt.Errorf("report contains an invalid issue")
		}
		switch strings.ToLower(issue.Severity) {
		case "critical":
			counts["critical"]++
		case "high":
			counts["high"]++
		case "medium":
			counts["medium"]++
		case "low":
			counts["low"]++
		case "unknown":
			counts["unknown"]++
		default:
			return fmt.Errorf("report contains an unsupported finding severity")
		}
	}
	for severity, count := range counts {
		rawCount, exists := summary[severity]
		if severity == "unknown" && count == 0 && !exists {
			continue
		}
		var actualCount int
		if !exists || json.Unmarshal(rawCount, &actualCount) != nil || actualCount != count {
			return fmt.Errorf("report findings summary is incomplete or inconsistent")
		}
	}
	return nil
}

type sessionCredentials struct {
	SessionID    string `json:"sessionId"`
	SessionToken string `json:"sessionToken"`
}

func createSession(ctx context.Context, endpoint, apiToken string) (sessionCredentials, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return sessionCredentials{}, fmt.Errorf("create scanner session request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+apiToken)
	response, err := newScannerHTTPClient(0).Do(request)
	if err != nil {
		return sessionCredentials{}, fmt.Errorf("create scanner session: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return sessionCredentials{}, fmt.Errorf("scanner backend session creation returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil {
		return sessionCredentials{}, fmt.Errorf("read scanner session response: %w", err)
	}
	if len(body) > 4096 {
		return sessionCredentials{}, fmt.Errorf("scanner session response exceeds 4096 bytes")
	}
	var credentials sessionCredentials
	if err := json.Unmarshal(body, &credentials); err != nil ||
		strings.TrimSpace(credentials.SessionID) == "" ||
		strings.TrimSpace(credentials.SessionToken) == "" {
		return sessionCredentials{}, fmt.Errorf("scanner backend returned an invalid session response")
	}
	return credentials, nil
}

func cleanupSession(
	ctx context.Context,
	endpoint string,
	apiToken string,
	session sessionCredentials,
) error {
	body, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("encode scanner session cleanup request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create scanner session cleanup request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+apiToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := newScannerHTTPClient(0).Do(request)
	if err != nil {
		return fmt.Errorf("clean up scanner session: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("scanner backend session cleanup returned HTTP %d", response.StatusCode)
	}
	return nil
}

func newScannerHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func uploadEndpoint(backendURL string) (string, error) {
	backendURL = strings.TrimSpace(backendURL)
	if backendURL == "" {
		return "", fmt.Errorf("%s is required to run a scan", BackendURLEnv)
	}

	parsed, err := url.Parse(backendURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%s must be an absolute HTTP or HTTPS base URL without credentials, query, or fragment", BackendURLEnv)
	}
	if parsed.Scheme == "http" {
		host := parsed.Hostname()
		ip := net.ParseIP(host)
		if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
			return "", fmt.Errorf("%s must use HTTPS unless the backend host is localhost or a loopback IP address", BackendURLEnv)
		}
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/api/upload"
	parsed.RawPath = ""
	return parsed.String(), nil
}

func createProjectArchive(ctx context.Context, projectPath string, excludedPaths []string) (archivePath string, resultErr error) {
	return createProjectArchiveWithLimits(ctx, projectPath, excludedPaths, defaultArchiveLimits())
}

func createProjectArchiveWithLimits(
	ctx context.Context,
	projectPath string,
	excludedPaths []string,
	limits ArchiveLimits,
) (archivePath string, resultErr error) {
	if ctx == nil {
		return "", fmt.Errorf("archive context cannot be nil")
	}
	resolvedLimits, err := resolveArchiveLimits(limits)
	if err != nil {
		return "", err
	}
	absoluteRoot, err := filepath.Abs(projectPath)
	if err != nil {
		return "", fmt.Errorf("resolve project directory: %w", err)
	}
	rootInfo, err := os.Lstat(absoluteRoot)
	if err != nil {
		return "", fmt.Errorf("inspect project directory: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return "", fmt.Errorf("project path must be a non-symlink directory")
	}

	exclusions := make(map[string]struct{}, len(excludedPaths))
	for _, excludedPath := range excludedPaths {
		absoluteExcluded := excludedPath
		if !filepath.IsAbs(absoluteExcluded) {
			absoluteExcluded = filepath.Join(absoluteRoot, absoluteExcluded)
		}
		absoluteExcluded, err = filepath.Abs(absoluteExcluded)
		if err != nil {
			return "", fmt.Errorf("resolve excluded path: %w", err)
		}
		relative, err := filepath.Rel(absoluteRoot, absoluteExcluded)
		if err == nil && filepath.IsLocal(relative) {
			exclusions[filepath.Clean(relative)] = struct{}{}
		}
	}

	archiveFile, err := os.CreateTemp("", "luminicent-project-*.zip")
	if err != nil {
		return "", fmt.Errorf("create temporary project archive: %w", err)
	}
	archivePath = archiveFile.Name()
	temporaryArchivePath := archivePath
	fileClosed := false
	defer func() {
		if !fileClosed {
			if closeErr := archiveFile.Close(); closeErr != nil {
				closeErr = fmt.Errorf("close temporary project archive: %w", closeErr)
				resultErr = errors.Join(resultErr, closeErr)
			}
		}
		if resultErr != nil {
			if removeErr := os.Remove(temporaryArchivePath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				resultErr = errors.Join(resultErr, fmt.Errorf("remove incomplete project archive: %w", removeErr))
			}
			archivePath = ""
		}
	}()

	limitedArchive := &archiveLimitWriter{writer: archiveFile, limit: resolvedLimits.CompressedBytes}
	archive := zip.NewWriter(limitedArchive)
	archiveEntries := 0
	expandedBytes := int64(0)
	err = filepath.WalkDir(absoluteRoot, func(filePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("read project path: %w", walkErr)
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		relative, err := filepath.Rel(absoluteRoot, filePath)
		if err != nil {
			return fmt.Errorf("resolve project-relative path: %w", err)
		}
		if relative == "." {
			return nil
		}
		if !filepath.IsLocal(relative) {
			return fmt.Errorf("project path escapes its root")
		}
		if isExcludedPath(relative, exclusions) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect project file %q: %w", relative, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("project contains unsupported symbolic link %q", relative)
		}
		if !entry.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("project contains unsupported file type at %q", relative)
		}
		if entry.IsDir() && isUnnecessaryDirectory(relative) {
			return filepath.SkipDir
		}
		if isSensitiveFile(relative) {
			return nil
		}
		if len(strings.Split(filepath.ToSlash(relative), "/")) > MaxArchivePathDepth {
			return fmt.Errorf("project path %q exceeds the maximum archive path depth of %d", relative, MaxArchivePathDepth)
		}
		if archiveEntries >= resolvedLimits.Entries {
			return fmt.Errorf("project exceeds the configured archive entry limit of %d", resolvedLimits.Entries)
		}
		archiveEntries++

		name := filepath.ToSlash(relative)
		if path.IsAbs(name) || path.Clean(name) != name || strings.HasPrefix(name, "../") {
			return fmt.Errorf("unsafe project-relative archive path %q", name)
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return fmt.Errorf("create archive header for %q: %w", relative, err)
		}
		header.Name = name
		if entry.IsDir() {
			header.Name += "/"
			header.Method = zip.Store
			_, err = archive.CreateHeader(header)
			if err != nil {
				return fmt.Errorf("add project directory %q to archive: %w", relative, err)
			}
			return nil
		}
		if info.Size() < 0 || info.Size() > resolvedLimits.IndividualFile {
			return fmt.Errorf("project file %q exceeds the configured per-file size limit", relative)
		}
		if info.Size() > resolvedLimits.ExpandedBytes-expandedBytes {
			return fmt.Errorf("project exceeds the configured expanded archive size limit")
		}
		expandedBytes += info.Size()
		header.Method = zip.Deflate
		writer, err := archive.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("add project file %q to archive: %w", relative, err)
		}
		file, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("open project file %q: %w", relative, err)
		}
		openedInfo, statErr := file.Stat()
		if statErr != nil {
			return errors.Join(
				fmt.Errorf("inspect opened project file %q: %w", relative, statErr),
				wrapCloseError(relative, file.Close()),
			)
		}
		if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
			return errors.Join(
				fmt.Errorf("project file %q changed while creating the archive", relative),
				wrapCloseError(relative, file.Close()),
			)
		}
		if openedInfo.Size() != info.Size() {
			return errors.Join(
				fmt.Errorf("project file %q changed while creating the archive", relative),
				wrapCloseError(relative, file.Close()),
			)
		}
		copied, copyErr := io.Copy(writer, io.LimitReader(contextReader{ctx: ctx, reader: file}, info.Size()+1))
		closeErr := file.Close()
		if copyErr != nil {
			return errors.Join(
				fmt.Errorf("archive project file %q: %w", relative, copyErr),
				wrapCloseError(relative, closeErr),
			)
		}
		if copied != info.Size() {
			return errors.Join(
				fmt.Errorf("project file %q changed while creating the archive", relative),
				wrapCloseError(relative, closeErr),
			)
		}
		if closeErr != nil {
			return fmt.Errorf("close project file %q: %w", relative, closeErr)
		}
		return nil
	})
	if err != nil {
		if closeErr := archive.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close incomplete project archive: %w", closeErr))
		}
		return "", err
	}
	if err := archive.Close(); err != nil {
		return "", fmt.Errorf("finish project archive: %w", err)
	}
	if err := archiveFile.Sync(); err != nil {
		return "", fmt.Errorf("flush project archive: %w", err)
	}
	if err := archiveFile.Close(); err != nil {
		fileClosed = true
		return "", fmt.Errorf("close project archive: %w", err)
	}
	fileClosed = true
	return archivePath, nil
}

func wrapCloseError(relative string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("close project file %q: %w", relative, err)
}

func defaultArchiveLimits() ArchiveLimits {
	return ArchiveLimits{
		CompressedBytes: MaxCompressedBytes,
		ExpandedBytes:   MaxExpandedBytes,
		Entries:         MaxArchiveEntries,
		IndividualFile:  MaxIndividualFile,
	}
}

func resolveArchiveLimits(configured ArchiveLimits) (ArchiveLimits, error) {
	defaults := defaultArchiveLimits()
	if configured.CompressedBytes == 0 {
		configured.CompressedBytes = defaults.CompressedBytes
	}
	if configured.ExpandedBytes == 0 {
		configured.ExpandedBytes = defaults.ExpandedBytes
	}
	if configured.Entries == 0 {
		configured.Entries = defaults.Entries
	}
	if configured.IndividualFile == 0 {
		configured.IndividualFile = defaults.IndividualFile
	}
	if configured.CompressedBytes < 0 || configured.CompressedBytes > MaxCompressedBytes ||
		configured.ExpandedBytes < 0 || configured.ExpandedBytes > MaxExpandedBytes ||
		configured.Entries < 0 || configured.Entries > MaxArchiveEntries ||
		configured.IndividualFile < 0 || configured.IndividualFile > MaxIndividualFile {
		return ArchiveLimits{}, fmt.Errorf("archive limits must be positive and cannot exceed backend upload limits")
	}
	if configured.CompressedBytes == 0 || configured.ExpandedBytes == 0 ||
		configured.Entries == 0 || configured.IndividualFile == 0 {
		return ArchiveLimits{}, fmt.Errorf("archive limits must be positive")
	}
	return configured, nil
}

type archiveLimitWriter struct {
	writer  io.Writer
	limit   int64
	written int64
}

func (w *archiveLimitWriter) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	remaining := w.limit - w.written
	if remaining <= 0 {
		return 0, errCompressedArchiveLimit
	}
	if int64(len(data)) > remaining {
		written, err := w.writer.Write(data[:int(remaining)])
		w.written += int64(written)
		if err != nil {
			return written, err
		}
		if written != int(remaining) {
			return written, io.ErrShortWrite
		}
		return written, errCompressedArchiveLimit
	}
	written, err := w.writer.Write(data)
	w.written += int64(written)
	if written < len(data) && err == nil {
		err = io.ErrShortWrite
	}
	return written, err
}

func isExcludedPath(relative string, exclusions map[string]struct{}) bool {
	cleaned := filepath.Clean(relative)
	for excluded := range exclusions {
		if strings.EqualFold(cleaned, excluded) ||
			strings.HasPrefix(strings.ToLower(cleaned), strings.ToLower(excluded)+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func isUnnecessaryDirectory(relative string) bool {
	switch strings.ToLower(filepath.Base(relative)) {
	case ".git", ".luminicent", ".ssh", ".aws", ".azure", ".kube", ".docker", ".gnupg",
		"node_modules", ".cache", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
		".venv", "venv":
		return true
	default:
		return false
	}
}

func isSensitiveFile(relative string) bool {
	name := strings.ToLower(filepath.Base(relative))
	ext := strings.ToLower(filepath.Ext(name))

	if name == ".env" || strings.HasPrefix(name, ".env.") || name == ".envrc" ||
		name == "project.env" || strings.HasPrefix(name, "project.env.") || strings.HasSuffix(name, ".env") {
		return true
	}
	switch name {
	case ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".htpasswd", ".pgpass":
		return true
	}
	switch ext {
	case ".pem", ".key", ".p12", ".pfx", ".ppk", ".p8", ".jks", ".keystore":
		return true
	}
	if strings.HasPrefix(name, "id_rsa") || strings.HasPrefix(name, "id_ed25519") ||
		strings.HasPrefix(name, "id_ecdsa") {
		return true
	}
	if name == "credentials" || name == ".credentials" || strings.HasPrefix(name, "credentials.") ||
		strings.HasPrefix(name, ".credentials.") || name == "secret" || name == "secrets" ||
		strings.HasPrefix(name, "secret.") || strings.HasPrefix(name, "secrets.") {
		return true
	}
	switch ext {
	case ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg", ".properties", ".xml":
		return strings.Contains(name, "credential") || strings.Contains(name, "secret") ||
			strings.Contains(name, "service-account")
	}
	return false
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

var _ Scanner = (*Client)(nil)
