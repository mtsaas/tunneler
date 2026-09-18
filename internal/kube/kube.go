// Package kube fronts a cluster's Kubernetes API.
//
// A request from kubectl passes through two halves, one in each of
// tunneler's servers:
//
//	kubectl → Gateway (coordinator) ══tunnel══▶ APIServer (exit node) → kube-apiserver
//
// The Gateway knows who is asking. It decides nothing itself: it tells the
// cluster who the user is, with Kubernetes' impersonation headers, and
// leaves authorization to the cluster's own RBAC. It records every request.
//
// The APIServer holds the one credential involved, the exit node's service
// account token, which therefore never leaves the cluster. It refuses to
// impersonate any group it was not configured to, which bounds what a
// compromised coordinator could make itself.
//
// Because the user is impersonated, the cluster's own audit log names them
// too, alongside the exit node that acted for them.
package kube

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Impersonation headers, as the Kubernetes API server reads them.
const (
	headerUser        = "Impersonate-User"
	headerGroup       = "Impersonate-Group"
	impersonatePrefix = "Impersonate-" // also -Uid and -Extra-*
)

// stripIdentity removes everything by which a request could say who it is
// from. Both halves call it before adding what they vouch for themselves.
func stripIdentity(h http.Header) {
	h.Del("Authorization")
	for name := range h {
		if strings.HasPrefix(name, impersonatePrefix) {
			h.Del(name)
		}
	}
}

// WriteStatus answers a request with a Kubernetes Status object, which is
// how kubectl expects to be told of a failure: it prints the message.
func WriteStatus(w http.ResponseWriter, code int, message string) {
	reason := map[int]string{
		http.StatusUnauthorized:       "Unauthorized",
		http.StatusForbidden:          "Forbidden",
		http.StatusNotFound:           "NotFound",
		http.StatusBadGateway:         "ServiceUnavailable",
		http.StatusServiceUnavailable: "ServiceUnavailable",
	}[code]
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{
		"kind":       "Status",
		"apiVersion": "v1",
		"metadata":   map[string]any{},
		"status":     "Failure",
		"message":    message,
		"reason":     reason,
		"code":       code,
	})
}
