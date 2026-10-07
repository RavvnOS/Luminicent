package api

import "context"

func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var response HealthResponse
	if err := c.do(ctx, "GET", "/api/health", nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}
