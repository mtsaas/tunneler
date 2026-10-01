package coordinator

import (
	"context"
	"net"
	"net/http"
	"net/url"

	"github.com/mtsaas/tunneler/internal/api"
)

func (c *Client) CreateShare(ctx context.Context, request api.ShareRequest) (*api.Share, error) {
	var share api.Share
	err := c.do(ctx, http.MethodPost, pathShares, true, request, &share)
	return &share, err
}

func (c *Client) Shares(ctx context.Context) ([]api.Share, error) {
	var shares []api.Share
	err := c.do(ctx, http.MethodGet, pathShares, true, nil, &shares)
	return shares, err
}

func (c *Client) Share(ctx context.Context, id string) (*api.Share, error) {
	var share api.Share
	err := c.do(ctx, http.MethodGet, pathShare(id), true, nil, &share)
	return &share, err
}

func (c *Client) ShareOperation(ctx context.Context, requestID string) (*api.Share, error) {
	var share api.Share
	err := c.do(ctx, http.MethodGet, pathShareOperation(requestID), true, nil, &share)
	return &share, err
}

func (c *Client) StopShare(ctx context.Context, id string) (*api.Share, error) {
	var share api.Share
	err := c.do(ctx, http.MethodDelete, pathShare(id), true, nil, &share)
	return &share, err
}

func (c *Client) RenewShare(ctx context.Context, id, generation string) (*api.Share, error) {
	var share api.Share
	err := c.do(ctx, http.MethodPost, pathShare(id)+"/renew", true, api.ShareRenewRequest{Generation: generation}, &share)
	return &share, err
}

// PublisherControl opens this share's single control generation. The caller
// must keep it alive; losing it ends the publication.
func (c *Client) PublisherControl(ctx context.Context, id string) (net.Conn, error) {
	return dialStream(ctx, c.Server+pathShare(id)+"/control", c.Token)
}

// PublisherData answers one pending dial with an opaque byte stream.
func (c *Client) PublisherData(ctx context.Context, id, generation, serviceID, connectionID string) (net.Conn, error) {
	q := url.Values{"generation": {generation}, "service": {serviceID}, "connection": {connectionID}}
	return dialStream(ctx, c.Server+pathShare(id)+"/data?"+q.Encode(), c.Token)
}

func (c *Client) PublisherResult(ctx context.Context, id string, result api.PublisherResult) error {
	return c.do(ctx, http.MethodPost, pathShare(id)+"/result", true, result, nil)
}
