package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sahilcyber-code/Luminicent/cli/internal/config"
)

type Client struct {
	BaseURL       string
	HTTPClient    *http.Client
	Token         string
	SessionCookie string
}

func NewClient(baseURL string, httpClient *http.Client) *Client {
	if baseURL == "" {
		baseURL = config.DefaultAPIURL
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: httpClient,
	}
}

func (c *Client) newRequest(ctx context.Context, method, target string, payload any) (*http.Request, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		request.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if c.SessionCookie != "" {
		request.Header.Set("Cookie", c.SessionCookie)
	}
	return request, nil
}

func (c *Client) do(ctx context.Context, method, path string, payload any, out any) error {
	if c == nil {
		return errors.New("api client is nil")
	}
	if c.BaseURL == "" {
		c.BaseURL = config.DefaultAPIURL
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}

	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		path = c.BaseURL + path
	}

	request, err := c.newRequest(ctx, method, path, payload)
	if err != nil {
		return err
	}

	response, err := c.HTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	body, readErr := io.ReadAll(response.Body)
	if readErr != nil {
		return readErr
	}

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		apiErr := &APIError{StatusCode: response.StatusCode}
		if len(body) > 0 {
			apiErr.ResponseBody = string(body)
			if decoded, ok := parseErrorMessage(body); ok {
				apiErr.Message = decoded
			}
		}
		if apiErr.Message == "" {
			apiErr.Message = fmt.Sprintf("request failed with status %d", response.StatusCode)
		}
		return apiErr
	}

	if out == nil || len(body) == 0 {
		return nil
	}

	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func parseErrorMessage(body []byte) (string, bool) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", false
	}
	for _, key := range []string{"error", "message"} {
		if value, ok := payload[key]; ok {
			if str, ok := value.(string); ok && str != "" {
				return str, true
			}
		}
	}
	return "", false
}

func (c *Client) Upload(ctx context.Context, filePath, sessionID string) (*UploadResponse, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(part, file); err != nil {
		return nil, err
	}
	if err := writer.WriteField("sessionId", sessionID); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/upload", &body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	if c.Token != "" {
		request.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if c.SessionCookie != "" {
		request.Header.Set("Cookie", c.SessionCookie)
	}

	response, err := c.HTTPClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	payload, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		apiErr := &APIError{StatusCode: response.StatusCode, ResponseBody: string(payload)}
		if msg, ok := parseErrorMessage(payload); ok {
			apiErr.Message = msg
		}
		return nil, apiErr
	}

	var result UploadResponse
	if err := json.Unmarshal(payload, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) BuildGitHubLoginURL(redirectURI string) string {
	base := strings.TrimRight(c.BaseURL, "/") + "/api/github/login"
	if redirectURI == "" {
		return base
	}
	values := url.Values{}
	values.Set("redirect_uri", redirectURI)
	return base + "?" + values.Encode()
}
