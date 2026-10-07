package api

import (
	"context"
	"fmt"
)

func (c *Client) Analyze(ctx context.Context, owner, repo string) error {
	_ = ctx
	_ = owner
	_ = repo
	return fmt.Errorf("%w: no dedicated /api/analyze endpoint exists in the current backend; production readiness analysis is performed during upload/deploy flows and returned in the deployment report payloads", ErrNotImplemented)
}
