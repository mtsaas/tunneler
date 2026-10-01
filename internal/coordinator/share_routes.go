package coordinator

import "net/url"

const (
	routeShareCreate      = "POST /v1/shares"
	routeShareList        = "GET /v1/shares"
	routeShareGet         = "GET /v1/shares/{id}"
	routeShareStop        = "DELETE /v1/shares/{id}"
	routeShareOperation   = "GET /v1/share-operations/{requestID}"
	routeShareRenew       = "POST /v1/shares/{id}/renew"
	routePublisherControl = "GET /v1/shares/{id}/control"
	routePublisherData    = "GET /v1/shares/{id}/data"
	routePublisherResult  = "POST /v1/shares/{id}/result"
	pathShares            = "/v1/shares"
)

func pathShare(id string) string { return pathShares + "/" + url.PathEscape(id) }
func pathShareOperation(requestID string) string {
	return "/v1/share-operations/" + url.PathEscape(requestID)
}
