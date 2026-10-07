package api

import "errors"

var ErrNotImplemented = errors.New("not implemented")

type APIError struct {
	StatusCode   int
	Message      string
	ResponseBody string
}

func (e *APIError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Message != "" {
		return e.Message
	}
	if e.ResponseBody != "" {
		return e.ResponseBody
	}
	return "api request failed"
}

type HealthResponse struct {
	OK        bool   `json:"ok"`
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

type UploadResponse struct {
	Success   bool        `json:"success"`
	SessionID string      `json:"sessionId"`
	Message   string      `json:"message"`
	Report    interface{} `json:"report"`
}

type CleanupResponse struct {
	Success   bool   `json:"success"`
	SessionID string `json:"sessionId"`
	Message   string `json:"message"`
}

type GitHubDeployResponse struct {
	Success   bool        `json:"success"`
	SessionID string      `json:"sessionId"`
	Message   string      `json:"message"`
	Report    interface{} `json:"report"`
}

type GitHubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
	HTMLURL   string `json:"html_url"`
	Type      string `json:"type"`
}

type GitHubRepo struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	DefaultBranch string `json:"default_branch"`
	HTMLURL       string `json:"html_url"`
	Description   string `json:"description"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
}

type GitHubBranch struct {
	Name      string `json:"name"`
	Protected bool   `json:"protected"`
	Default   bool   `json:"default"`
}

type LogEntry struct {
	Type      string `json:"type"`
	Message   string `json:"message"`
	Timestamp int64  `json:"timestamp"`
}

type DeploymentSession struct {
	SessionID   string                 `json:"sessionId"`
	Status      string                 `json:"status"`
	StartedAt   int64                  `json:"startedAt,omitempty"`
	UpdatedAt   int64                  `json:"updatedAt,omitempty"`
	EndedAt     int64                  `json:"endedAt,omitempty"`
	DurationMS  int64                  `json:"durationMs,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Message     string                 `json:"message,omitempty"`
	Owner       string                 `json:"owner,omitempty"`
	Repo        string                 `json:"repo,omitempty"`
	Branch      string                 `json:"branch,omitempty"`
	ImageName   string                 `json:"imageName,omitempty"`
	ContainerID string                 `json:"containerId,omitempty"`
	Logs        []LogEntry             `json:"logs,omitempty"`
	Metrics     map[string]interface{} `json:"metrics,omitempty"`
}
