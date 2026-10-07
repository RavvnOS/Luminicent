package api

import (
	"context"
	"fmt"
)

func (c *Client) GetDeploymentLogs(ctx context.Context, sessionID string) ([]LogEntry, error) {
	return nil, fmt.Errorf("%w: deployment logs are emitted through the backend Socket.IO events such as status and terminal_output; no REST log endpoint exists in the current backend contract", ErrNotImplemented)
}
