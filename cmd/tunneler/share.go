package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/publisher"
)

type shareOptions struct {
	public, detach bool
	ttl, requestID string
	waitReady      time.Duration
}

type shareError struct {
	error
	code               string
	status             int
	shareID, requestID string
}

type shareServiceOutput struct {
	api.ShareService
	LocalTarget *string `json:"local_target"`
	State       string  `json:"state"`
}

type shareWorkerOutput struct {
	Mode  string `json:"mode"`
	ID    string `json:"local_worker_id"`
	State string `json:"state"`
}

type shareOutput struct {
	api.Share
	Services  []shareServiceOutput `json:"services"`
	Publisher *shareWorkerOutput   `json:"publisher"`
	Readiness struct {
		PublisherPathTCP   bool `json:"publisher_path_tcp"`
		PublicEdgeVerified bool `json:"public_edge_verified"`
	} `json:"readiness"`
}

func shareResult(s *api.Share, local *shareLocal) shareOutput {
	out := shareOutput{Share: *s, Services: make([]shareServiceOutput, 0, len(s.Services))}
	out.Readiness.PublisherPathTCP = s.State == "ready" && s.ReadyAt != nil
	for _, service := range s.Services {
		item := shareServiceOutput{ShareService: service, State: s.State}
		if local != nil {
			if target, ok := local.Targets[service.Name]; ok {
				item.LocalTarget = &target
			}
		}
		out.Services = append(out.Services, item)
	}
	if local != nil {
		out.Publisher = &shareWorkerOutput{local.Mode, local.WorkerID, local.State}
	}
	return out
}

func printShare(out shareOutput) {
	var lines []string
	lines = append(lines, fmt.Sprintf("Share %s (%s, %s), expires %s", out.ID, out.State, out.Access, out.ExpiresAt.Local().Format(time.DateTime)))
	for _, service := range out.Services {
		lines = append(lines, fmt.Sprintf("  %s: %s", service.Name, service.URL))
	}
	result(out, strings.Join(lines, "\n"))
}

func shareCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "share", Short: "Share temporary public URLs for localhost services", GroupID: groupCore}
	cmd.AddCommand(shareStartCmd(), shareListCmd(), shareInspectCmd(), shareStopCmd(), shareWorkerCmd())
	return cmd
}

func shareStartCmd() *cobra.Command {
	opts := shareOptions{}
	cmd := &cobra.Command{
		Use: "start [NAME=]PORT...", Short: "Publish localhost HTTP services until stopped or expired",
		Long: "Publish localhost HTTP services at temporary public HTTPS URLs. Anyone with a URL can connect. Readiness checks the publisher data path and local TCP ports; verify application health through the URL separately.",
		Args: usage(func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("provide a local port, for example: tunneler share start 8080")
			}
			return nil
		}),
		Annotations: map[string]string{
			helpArguments: "Use 8080, web=8080, web=:8080, web=localhost:8080, or web=[::1]:8080. Ports and localhost use 127.0.0.1. Remote addresses are refused. HTTP Upgrade and WebSockets are supported.",
			helpJSON:      "One complete readiness object with share_id, request_id, services, expires_at, publisher and readiness. --detach returns only after acknowledged worker handoff. Retry the same --request-id to recover an ambiguous result.",
		},
		Example: "$ tunneler share start 8080\n$ tunneler share start web=:3000 api=localhost:8080\n$ tunneler share start web=3000 --detach --request-id preview-42 --output json",
		RunE: func(cmd *cobra.Command, args []string) (returnErr error) {
			request, targets, err := parseShare(args, opts)
			if err != nil {
				return usageError{err}
			}
			var startupLocal *shareLocal
			var knownID string
			defer func() {
				if returnErr == nil {
					return
				}
				if apiErr := (*api.Error)(nil); errors.As(returnErr, &apiErr) && apiErr.Message == "publishing is disabled or access is denied" {
					returnErr = fmt.Errorf("%w; ask an administrator to configure sharing.domain and sharing.control_hosts, then enable sharing.allow_authenticated or add a matching sharing.grants entry", returnErr)
				}
				if startupLocal != nil {
					if snapshot := startupLocal.snapshot(); snapshot.Share != nil {
						knownID = snapshot.Share.ID
					}
				}
				code, status := classify(returnErr)
				if errors.Is(returnErr, context.DeadlineExceeded) {
					code, status = "startup_timeout", exitUnavailable
				}
				if existing := (shareError{}); errors.As(returnErr, &existing) {
					if existing.shareID != "" {
						knownID = existing.shareID
					}
				}
				returnErr = shareError{error: returnErr, code: code, status: status, shareID: knownID, requestID: request.RequestID}
			}()
			startupCtx, startupCancel := context.WithDeadline(cmd.Context(), request.StartupDeadline)
			defer startupCancel()
			c, err := authed(startupCtx)
			if err != nil {
				return err
			}
			if findShareLocal(c.Server, "", request.RequestID) == nil {
				existing, lookupErr := c.ShareOperation(startupCtx, request.RequestID)
				if lookupErr == nil {
					knownID = existing.ID
					request.StartupDeadline = existing.StartupDeadline
					verified, err := c.CreateShare(startupCtx, request)
					if err != nil {
						return err
					}
					local := &shareLocal{shareLocalData: shareLocalData{Server: c.Server, Request: request}}
					if verified.State == "ended" {
						return shareEnded(local, verified)
					}
					if verified.State == "ready" {
						printShare(shareResult(verified, nil))
						return nil
					}
					out, err := recoverShareStart(cmd.Context(), c, local)
					if err != nil {
						return err
					}
					printShare(out)
					return nil
				}
				if apiErr := (*api.Error)(nil); !errors.As(lookupErr, &apiErr) || apiErr.Status != http.StatusNotFound {
					return lookupErr
				}
			}
			local, existing, err := prepareShareLocal(c.Server, request, targets, opts.detach)
			if err != nil {
				return err
			}
			startupLocal = local
			if existing {
				out, err := recoverShareStart(cmd.Context(), c, local)
				if err != nil {
					return err
				}
				printShare(out)
				return nil
			}
			if opts.detach {
				out, err := detachShare(cmd.Context(), local)
				if err != nil {
					return err
				}
				printShare(out)
				return nil
			}
			return runShareLocal(cmd.Context(), c, local, func(publisherCtx context.Context, s *api.Share) error {
				if err := commitShareHandoff(publisherCtx, local, s); err != nil {
					return err
				}
				if err := publisherCtx.Err(); err != nil {
					return err
				}
				printShare(shareResult(s, local.snapshot()))
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&opts.public, "public", true, "Allow anyone with the URL to connect (private shares are not supported)")
	cmd.Flags().BoolVar(&opts.detach, "detach", false, "Keep a private worker running after this command exits")
	cmd.Flags().StringVar(&opts.ttl, "ttl", "", "Requested lifetime, such as 30m or 1h")
	cmd.Flags().StringVar(&opts.requestID, "request-id", "", "Unique operation ID; reuse only to recover the same start")
	cmd.Flags().DurationVar(&opts.waitReady, "wait-ready", 60*time.Second, "Maximum time to establish publisher readiness")
	return cmd
}

var shareName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`)

func parseShare(args []string, opts shareOptions) (api.ShareRequest, map[string]string, error) {
	request := api.ShareRequest{Access: "public", RequestID: opts.requestID, TTL: opts.ttl}
	if !opts.public {
		return request, nil, errors.New("private shares are not supported; omit --public=false to publish a public URL")
	}
	if opts.waitReady <= 0 {
		return request, nil, errors.New("--wait-ready must be positive")
	}
	if opts.ttl != "" {
		ttl, err := time.ParseDuration(opts.ttl)
		if err != nil || ttl <= 0 {
			return request, nil, errors.New("--ttl must be a positive duration")
		}
		request.TTL = ttl.String()
	}
	if request.RequestID == "" {
		request.RequestID = rand.Text()
	}
	if len(request.RequestID) < 8 || len(request.RequestID) > 128 || strings.TrimSpace(request.RequestID) != request.RequestID || strings.ContainsAny(request.RequestID, "\r\n\x00") {
		return request, nil, errors.New("--request-id must be 8–128 characters without surrounding whitespace")
	}
	targets := make(map[string]string, len(args))
	seen := make(map[string]bool)
	for _, arg := range args {
		name, target, named := strings.Cut(arg, "=")
		if !named {
			target, name = name, ""
		}
		original := target
		if !strings.Contains(target, ":") {
			target = ":" + target
		}
		host, portString, err := net.SplitHostPort(target)
		if err != nil {
			return request, nil, fmt.Errorf("invalid local target %q; use 8080, :8080, localhost:8080, or [::1]:8080", original)
		}
		if host == "" || strings.EqualFold(host, "localhost") {
			host = "127.0.0.1"
		}
		target = net.JoinHostPort(host, portString)
		if err := publisher.ValidateTarget(target); err != nil {
			return request, nil, fmt.Errorf("invalid local target %q: use a loopback address and a port from 1 to 65535", original)
		}
		numericPort, _ := strconv.Atoi(portString)
		portString = strconv.Itoa(numericPort)
		target = net.JoinHostPort(net.ParseIP(host).String(), portString)
		if name == "" && !named {
			name = "p" + portString
		}
		if !shareName.MatchString(name) {
			return request, nil, fmt.Errorf("service name %q must be a DNS label of at most 32 characters", name)
		}
		if _, ok := targets[name]; ok {
			return request, nil, fmt.Errorf("duplicate service name %q", name)
		}
		if seen[target] {
			return request, nil, fmt.Errorf("duplicate local target %q", target)
		}
		seen[target], targets[name] = true, target
		request.Services = append(request.Services, api.ShareServiceRequest{Name: name, Protocol: api.ShareProtocolHTTP})
	}
	sort.Slice(request.Services, func(i, j int) bool { return request.Services[i].Name < request.Services[j].Name })
	manifest, _ := json.Marshal(targets)
	digest := sha256.Sum256(manifest)
	request.ManifestDigest = hex.EncodeToString(digest[:])
	request.StartupDeadline = time.Now().Add(opts.waitReady)
	return request, targets, nil
}

func shareListCmd() *cobra.Command {
	return &cobra.Command{Use: "list", Short: "List your temporary shares", Args: usage(cobra.NoArgs), Example: "$ tunneler share list --output json", RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
		defer cancel()
		c, err := authed(ctx)
		if err != nil {
			return err
		}
		shares, err := c.Shares(ctx)
		if err != nil {
			return err
		}
		out := make([]shareOutput, 0, len(shares))
		var text []string
		for i := range shares {
			out = append(out, shareResult(&shares[i], findShareLocal(c.Server, shares[i].ID, shares[i].RequestID)))
			text = append(text, fmt.Sprintf("%s  %s  %s", shares[i].ID, shares[i].State, shares[i].ExpiresAt.Local().Format(time.DateTime)))
		}
		if len(text) == 0 {
			text = append(text, "No shares.")
		}
		result(out, strings.Join(text, "\n"))
		return nil
	}}
}

func shareInspectCmd() *cobra.Command {
	var operation bool
	cmd := &cobra.Command{Use: "inspect ID", Short: "Inspect a share or recover a start operation", Args: usage(cobra.ExactArgs(1)), Example: "$ tunneler share inspect shr_example --output json\n$ tunneler share inspect preview-42 --request-id --output json", RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
		defer cancel()
		c, err := authed(ctx)
		if err != nil {
			return err
		}
		var s *api.Share
		if operation {
			s, err = c.ShareOperation(ctx, args[0])
		} else {
			s, err = c.Share(ctx, args[0])
		}
		if err != nil {
			return err
		}
		printShare(shareResult(s, findShareLocal(c.Server, s.ID, s.RequestID)))
		return nil
	}}
	cmd.Flags().BoolVar(&operation, "request-id", false, "Interpret ID as the start operation's request ID")
	return cmd
}

type shareStopOutput struct {
	SchemaVersion   int          `json:"schema_version"`
	ID              string       `json:"share_id"`
	State           string       `json:"state"`
	LocalStopped    bool         `json:"local_stopped"`
	RemoteStopped   bool         `json:"remote_stopped"`
	CleanupDeadline *time.Time   `json:"cleanup_deadline"`
	Share           *shareOutput `json:"share,omitempty"`
}

func shareStopCmd() *cobra.Command {
	return &cobra.Command{Use: "stop ID", Short: "Stop a share and its local worker", Args: usage(cobra.ExactArgs(1)), Example: "$ tunneler share stop shr_example --output json", RunE: func(cmd *cobra.Command, args []string) error {
		c, err := loadClient()
		if err != nil {
			return err
		}
		local := findShareLocal(c.Server, args[0], "")
		out := shareStopOutput{SchemaVersion: 1, ID: args[0], State: "cleanup_pending"}
		if local != nil {
			if local.State == "ended" {
				out.LocalStopped = true
			} else {
				ipcCtx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
				out.LocalStopped = stopShareLocal(ipcCtx, local)
				cancel()
			}
			if local.Share != nil {
				deadline := local.Share.ExpiresAt
				if !deadline.IsZero() {
					out.CleanupDeadline = &deadline
				}
			}
		}
		remoteCtx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
		s, remoteErr := c.StopShare(remoteCtx, args[0])
		cancel()
		if remoteErr == nil {
			out.RemoteStopped, out.State, out.CleanupDeadline = true, "ended", nil
			value := shareResult(s, local)
			out.Share = &value
			result(out, "Share stopped.")
			return nil
		}
		if out.LocalStopped {
			result(out, "Local forwarding stopped; remote cleanup is pending.")
			return shareError{error: fmt.Errorf("remote revocation could not be confirmed: %w", remoteErr), code: "cleanup_pending", status: exitUnavailable, shareID: args[0]}
		}
		return remoteErr
	}}
}

func shareEnded(local *shareLocal, s *api.Share) error {
	return shareError{error: fmt.Errorf("share %s ended (%s); start a new request ID for a new share", s.ID, s.TerminalReason), code: "share_ended", status: exitUnavailable, shareID: s.ID, requestID: local.Request.RequestID}
}

func recoverShareStart(ctx context.Context, c *client, local *shareLocal) (shareOutput, error) {
	deadline := local.Request.StartupDeadline
	if local.State == "ready" || local.State == "ended" {
		deadline = time.Now().Add(5 * time.Second)
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	for {
		s, err := c.ShareOperation(ctx, local.Request.RequestID)
		if err == nil {
			if s.State == "ended" {
				return shareOutput{}, shareEnded(local, s)
			}
			if s.State == "ready" {
				current := findShareLocal(c.Server, s.ID, s.RequestID)
				if current != nil {
					ipcCtx, stop := context.WithTimeout(ctx, time.Second)
					reply, ipcErr := shareIPC(ipcCtx, current, "inspect")
					stop()
					if ipcErr == nil && reply.Local != nil {
						current = &shareLocal{shareLocalData: *reply.Local}
						if current.State == "starting" || current.State == "proposed" {
							select {
							case <-ctx.Done():
								return shareOutput{}, shareError{error: errors.New("worker ownership has not been acknowledged"), code: "startup_timeout", status: exitUnavailable, shareID: s.ID, requestID: s.RequestID}
							case <-time.After(100 * time.Millisecond):
								continue
							}
						}
						if current.State == "ended" {
							return shareOutput{}, shareError{error: errors.New("local publisher ended; inspect remote cleanup before starting a new request"), code: "share_ended", status: exitUnavailable, shareID: s.ID, requestID: s.RequestID}
						}
					} else {
						current = nil
					}
				}
				return shareResult(s, current), nil
			}
		} else if e := (*api.Error)(nil); !errors.As(err, &e) || e.Status != http.StatusNotFound {
			return shareOutput{}, err
		}
		select {
		case <-ctx.Done():
			return shareOutput{}, shareError{error: errors.New("start outcome is not ready; inspect this request ID before retrying with a new one"), code: "startup_timeout", status: exitUnavailable, requestID: local.Request.RequestID}
		case <-time.After(100 * time.Millisecond):
		}
	}
}
