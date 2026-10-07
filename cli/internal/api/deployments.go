package api

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
)

func (c *Client) Cleanup(ctx context.Context, sessionID string) (*CleanupResponse, error) {
	var response CleanupResponse
	if sessionID == "" {
		return nil, fmt.Errorf("sessionId is required")
	}
	if err := c.do(ctx, "POST", "/api/cleanup", map[string]string{"sessionId": sessionID}, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) StopDeployment(ctx context.Context, sessionID string) (*CleanupResponse, error) {
	return c.Cleanup(ctx, sessionID)
}

func (c *Client) ListDeployments(ctx context.Context) ([]DeploymentSession, error) {
	var response []DeploymentSession
	if err := c.do(ctx, "GET", "/api/github/deployments", nil, &response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *Client) GetDeployment(ctx context.Context, sessionID string) (*DeploymentSession, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("sessionId is required")
	}
	var response DeploymentSession
	if err := c.do(ctx, "GET", "/api/github/deployments/"+sessionID, nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) GetGitHubUser(ctx context.Context) (*GitHubUser, error) {
	var response GitHubUser
	if err := c.do(ctx, "GET", "/api/github/user", nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) ListGitHubRepos(ctx context.Context, page, perPage int) ([]GitHubRepo, error) {
	params := url.Values{}
	if page > 0 {
		params.Set("page", strconv.Itoa(page))
	}
	if perPage > 0 {
		params.Set("per_page", strconv.Itoa(perPage))
	}
	path := "/api/github/repos"
	if params.Encode() != "" {
		path += "?" + params.Encode()
	}
	var response []GitHubRepo
	if err := c.do(ctx, "GET", path, nil, &response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *Client) ListGitHubBranches(ctx context.Context, owner, repo string) ([]GitHubBranch, error) {
	if owner == "" || repo == "" {
		return nil, fmt.Errorf("owner and repo are required")
	}
	path := "/api/github/branches?owner=" + url.QueryEscape(owner) + "&repo=" + url.QueryEscape(repo)
	var response []GitHubBranch
	if err := c.do(ctx, "GET", path, nil, &response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *Client) DeployGitHubRepo(ctx context.Context, owner, repo, branch, sessionID string) (*GitHubDeployResponse, error) {
	if owner == "" || repo == "" || branch == "" {
		return nil, fmt.Errorf("owner, repo, and branch are required")
	}
	payload := map[string]string{"owner": owner, "repo": repo, "branch": branch}
	if sessionID != "" {
		payload["sessionId"] = sessionID
	}
	var response GitHubDeployResponse
	if err := c.do(ctx, "POST", "/api/github/deploy", payload, &response); err != nil {
		return nil, err
	}
	return &response, nil
}
