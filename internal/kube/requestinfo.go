package kube

import (
	"net/http"
	"strings"
)

// RequestInfo is what a request to the Kubernetes API is about, in the terms
// of Kubernetes' own audit log and RBAC.
type RequestInfo struct {
	// Verb is get, list, watch, create, update, patch, delete or
	// deletecollection for a resource request, and the lower-case HTTP
	// method otherwise.
	Verb string
	// IsResource reports whether the request is for a resource, as opposed
	// to a path like /version or /openapi/v2.
	IsResource  bool
	APIGroup    string // "" for the core group
	APIVersion  string
	Namespace   string // "" for cluster-scoped resources, and for all namespaces
	Resource    string // plural, as in the path: pods
	Subresource string // exec, log, status, ...
	Name        string
	Path        string // the path as requested
}

// ParseRequest works out what r is about from its method, path and query. It
// follows the rules of the API server's own request info resolver.
func ParseRequest(r *http.Request) RequestInfo {
	info := RequestInfo{Path: r.URL.Path, Verb: strings.ToLower(r.Method)}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")

	// /api/VERSION/... is the core group; /apis/GROUP/VERSION/... the rest.
	switch {
	case len(parts) >= 3 && parts[0] == "api":
		info.APIVersion, parts = parts[1], parts[2:]
	case len(parts) >= 4 && parts[0] == "apis":
		info.APIGroup, info.APIVersion, parts = parts[1], parts[2], parts[3:]
	default:
		return info // discovery, /version, /healthz, /openapi, ...
	}
	info.IsResource = true

	// The legacy /watch/ prefix, which kubectl no longer sends.
	watch := false
	if parts[0] == "watch" && len(parts) > 1 {
		watch, parts = true, parts[1:]
	}
	// namespaces/NS/RESOURCE/... scopes the rest, but namespaces/NS alone, or
	// with a subresource of the namespace itself, is about the namespace.
	if parts[0] == "namespaces" && len(parts) > 2 && parts[2] != "status" && parts[2] != "finalize" {
		info.Namespace, parts = parts[1], parts[2:]
	}
	info.Resource = parts[0]
	if len(parts) > 1 {
		info.Name = parts[1]
	}
	if len(parts) > 2 {
		info.Subresource = parts[2]
	}
	if info.Resource == "namespaces" && info.Namespace == "" {
		info.Namespace = info.Name // Kubernetes treats a namespace as being in itself
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		q := r.URL.Query().Get("watch")
		switch {
		case watch || q == "true" || q == "1":
			info.Verb = "watch"
		case info.Name == "":
			info.Verb = "list"
		default:
			info.Verb = "get"
		}
	case http.MethodPost:
		info.Verb = "create"
	case http.MethodPut:
		info.Verb = "update"
	case http.MethodPatch:
		info.Verb = "patch"
	case http.MethodDelete:
		info.Verb = "delete"
		if info.Name == "" {
			info.Verb = "deletecollection"
		}
	}
	return info
}
