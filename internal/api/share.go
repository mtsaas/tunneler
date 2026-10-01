package api

import "time"

const ShareProtocolHTTP = "http"

// ShareServiceRequest describes a public frontend, not a local dial target.
type ShareServiceRequest struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol,omitempty"`
}

// ShareRequest identifies one immutable operation. Retrying it cannot extend
// its startup deadline or allocate another share.
type ShareRequest struct {
	Services        []ShareServiceRequest `json:"services"`
	ManifestDigest  string                `json:"manifest_digest"`
	TTL             string                `json:"ttl,omitempty"`
	Access          string                `json:"access"`
	RequestID       string                `json:"request_id"`
	StartupDeadline time.Time             `json:"startup_deadline"`
}

type ShareService struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	URL         string `json:"url"`
	LocalTarget string `json:"local_target,omitempty"`
}

// Share is public metadata; publisher credentials never belong here.
type Share struct {
	SchemaVersion         int            `json:"schema_version"`
	ID                    string         `json:"share_id"`
	Owner                 string         `json:"owner"`
	RequestID             string         `json:"request_id"`
	BootID                string         `json:"coordinator_boot_id"`
	State                 string         `json:"state"`
	Access                string         `json:"access"`
	Services              []ShareService `json:"services"`
	ExpiresAt             time.Time      `json:"expires_at"`
	StartupDeadline       time.Time      `json:"startup_deadline"`
	ReadyAt               *time.Time     `json:"ready_at,omitempty"`
	AuthorizationDeadline time.Time      `json:"authorization_deadline"`
	Generation            string         `json:"generation,omitempty"`
	TerminalReason        string         `json:"terminal_reason,omitempty"`
}

type ShareRenewRequest struct {
	Generation string `json:"generation"`
}

// PublisherMessage selects a registered service ID. HTTP parsing belongs to
// the public frontend; the publisher always supplies opaque byte streams.
type PublisherMessage struct {
	Type         string `json:"type"`
	Generation   string `json:"generation,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"`
	ServiceID    string `json:"service_id,omitempty"`
	Share        *Share `json:"share,omitempty"`
	Error        string `json:"error,omitempty"`
}

type PublisherReply struct {
	Type string `json:"type"`
}

type PublisherResult struct {
	Generation   string `json:"generation"`
	ConnectionID string `json:"connection_id"`
	ServiceID    string `json:"service_id"`
	Error        string `json:"error"`
}
