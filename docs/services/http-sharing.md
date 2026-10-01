# Share local HTTP services

`tunneler share` publishes one or more services on your computer through
temporary HTTPS URLs. Each named service gets its own hostname. HTTP requests,
streaming responses, WebSockets, and HTTP Upgrade connections pass through the
coordinator to the local port.

The URLs are public. Anyone who obtains one can reach the application until the
share ends. The application keeps its own authentication. Public access is the
default; `--public` is optional. The coordinator must permit your account to publish.

## Start a share

Configure the coordinator and sign in as usual:

```sh
tunneler config --server https://tunneler.example.com
tunneler auth login
```

Start your local services, then publish their ports:

```sh
tunneler share start 8080
# Or name several services:
tunneler share start web=:3000 api=localhost:8080 --ttl 1h
```

The command prints a URL for each service after the coordinator can dial each
local port through the tunnel. It keeps running until you press Ctrl-C or the
share ends. A bare port, such as `3000`, gets the name `p3000`.

`8080`, `:8080`, and `localhost:8080` all use `127.0.0.1:8080`, without DNS
resolution. Explicit loopback addresses, including `[::1]:8080`, are also accepted;
remote addresses and other DNS names are refused. The service must accept plain HTTP
on that local port. HTTPS protects the public URL and the connection from your
computer to the coordinator.

Some development servers restrict the Host or Origin header. Configure their
allowed hosts and origins for your generated preview URL. Tunneler preserves
those headers and the application's Authorization and Cookie headers.

Readiness means the publisher path and local TCP connection succeeded. It does
not verify application responses or public DNS. Open the returned URL to check
the application.

## Use from an agent

Detached mode returns after the publisher is ready and continues independently
of the invoking process:

```sh
tunneler share start web=3000 api=8080 --detach \
  --ttl 30m --request-id 897c5b24-0ba7-4709-b86e-66106f54a037 --output json
tunneler share list --output json
tunneler share inspect <share-id> --output json
tunneler share stop <share-id> --output json
```

Save the `share_id`, `expires_at`, and service URLs from the result. Use a unique
request ID for each intended share; retry that same operation with the same
arguments after an uncertain response. Repeating an operation does not extend
its lifetime or create another share. Reusing its ID with changed inputs fails.

To recover using only the request ID:

```sh
tunneler share inspect 897c5b24-0ba7-4709-b86e-66106f54a037 --request-id --output json
```

Results go to stdout; errors and diagnostics go to stderr. Commands do not open
login prompts. If authentication has expired and cannot renew, run
`tunneler auth login` before starting another share.

`stop` can run on another computer using the owner's login. It closes the
public routes and their active connections. If the coordinator is unreachable,
the CLI can stop a publisher on the local computer and reports that remote
cleanup is pending. The coordinator's liveness and authorization deadlines
bound that cleanup.

## Lifetime

The default TTL is one hour. The administrator can change the default and
maximum. Each share also renews a shorter authorization lease while its
publisher remains connected and logged in.

Stop, expiry, publisher disconnection, denied renewal, or coordinator restart
ends the share. Tunneler does not reconnect or create a replacement silently.
Start another share to obtain new URLs. The coordinator retains operation
records for a bounded period so that interrupted start requests remain
recoverable; it does not restore live previews after restart.

## Configure the coordinator

Sharing is disabled until `sharing` is configured. To let every authenticated
user publish, enable `allow_authenticated`:

```json
{
  "sharing": {
    "domain": "share.tunneler.example.com",
    "control_hosts": ["tunneler.example.com"],
    "default_ttl": "1h",
    "max_ttl": "8h",
    "allow_authenticated": true
  }
}
```

Add this object to the existing coordinator configuration. The option defaults
to false. With it disabled, `grants` can name explicit publishers, for example
`[{"group": "<developer-group-id>"}, {"user": "<user-id>"}]`. Each grant names
exactly one `user` or `group`; these grants are separate from cluster grants.
Disabling `allow_authenticated` ends active shares whose owners lack a publishing
grant. Management and publication always require an authenticated owner;
visitors to public URLs require no coordinator authentication.

If startup reports `sharing_disabled`, configure the sharing domain, control
hosts, wildcard DNS/TLS, and publishing access on the coordinator. Installing a
new CLI or coordinator version does not configure these deployment settings.
If it reports `access_denied`, enable `sharing.allow_authenticated` or add a
matching `sharing.grants` entry. Cluster access and administrator status do not
grant publishing permission automatically.

`control_hosts` names the coordinator's canonical
hosts; the generated preview hosts serve application traffic, including paths
such as `/v1`, without exposing management routes.

### Choose the sharing domain

Sharing is an operator opt-in. `sharing.domain` chooses the hostname suffix and
the browser cookie boundary. Same-zone layouts are supported: keep the control
host at `tunneler.example.com` and publish at `*.share.tunneler.example.com`.
Configure wildcard DNS and a wildcard TLS certificate for those preview hosts,
then route them to the same coordinator. No additional opt-in flag is required.

Same-zone hosts can share parent-domain cookies. An application can set
`Domain=tunneler.example.com` or `Domain=example.com`, and browsers can send those
cookies to the control host. Cookies already scoped to those parent domains can
also reach the shared application. Host-only application cookies work normally.
`HttpOnly` and `SameSite` do not provide a boundary between these same-site hosts.
See the [HTTP cookie specification](https://www.rfc-editor.org/rfc/rfc6265.html#section-8.6).

The operator decides whether applications can share that cookie boundary. For
browser isolation, use another registrable domain, such as `share.example.net`,
with wildcard DNS/TLS pointing to the same coordinator. A deeper subdomain or
delegated DNS zone under `example.com` does not change browser cookie scope.

Tunneler authenticates publishers and management requests with bearer tokens,
not browser cookies. The proxy preserves application cookies without rewriting
them or injecting CSP restrictions. Preview hosts dispatch every path, including
`/v1`, to the application; unknown and retired preview hosts return 404.
Forwarded host headers cannot select control routes. A canonical control host
cannot equal `sharing.domain` or lie within its preview namespace, because those
hosts must have unambiguous routing.

For the Helm chart:

```yaml
config:
  sharing:
    domain: share.tunneler.example.com
    control_hosts: [tunneler.example.com]
    allow_authenticated: true
ingress:
  enabled: true
  host: tunneler.example.com
  tlsSecretName: coordinator-tls
  preview:
    enabled: true
    tlsSecretName: preview-wildcard-tls
```

The preview ingress uses the same ingress class and a separate annotations map.
Configure streaming and idle timeouts for your controller. Verify ordinary
HTTP, WebSockets, and your application's Upgrade protocol through the actual
ingress before relying on it. WebSocket support alone does not establish that
an ingress accepts every custom Upgrade token.

### Bring your own TLS edge

Leave `ingress.enabled` false when your deployment manages routing separately.
Sharing does not depend on Kubernetes Ingress or a particular proxy. Configure
your edge to terminate TLS for the canonical control host and the wildcard
preview host, then forward both to the same coordinator HTTP listener. In the
Helm chart, that listener is the Service's named `http` port.

Preserve the original Host header and route every application path, including
`/v1`, through the preview hostname. Do not rewrite preview traffic to the
control hostname. Do not put a coordinator login gate on public preview routes;
the application can enforce its own authentication.

Every proxy hop must pass WebSockets and any custom HTTP Upgrade token used by
your application. Keep the upstream connection to the coordinator on HTTP/1.1
for Upgrade traffic. Avoid request or response buffering on these routes.
Disable automatic retries for application requests that must run only once.

Configure stream and idle timeouts for the intended lifetime of quiet
connections, separately from request timeouts. An edge can close a connection
before the share TTL; publisher readiness does not check these settings. After
deployment, verify HTTPS, streaming, WebSocket and custom Upgrade traffic, idle
behavior, and connection termination after stop or expiry.

Deploy the coordinator image and chart from a release that includes sharing.
An older binary does not gain this feature from new chart values. Keep the
single coordinator and its persistent volume: generated hosts and live
publisher sockets belong to that process.

Connection, pending-dial, service, and operation-record limits are configurable.
The coordinator runs as one replica, as with the existing cluster tunnel
registry.

Share creation and public request admission require a working coordinator
audit sink. If it cannot record the action, the coordinator returns 503 before
publishing the share or forwarding application traffic. Stop and expiry still
close connections when the audit sink is unavailable.

Connection limits bound both backend sockets and active or queued visitor
requests, with separate accounting for each. Saturated preview routes return
503 instead of accumulating unbounded waiting handlers. Defaults allow 32
connections or requests per share, 128 per owner, and 1,024 across the coordinator.

The ledger retains ended shares so start retries cannot accidentally publish a
replacement. Its default limits are 128 records per owner
(`max_operation_records_per_user`) and 4,096 total (`max_operation_records`).
Stopping a share frees its live-share and connection slots, but its retry record
counts until retention expires. Replaying an existing operation does not
allocate another record. An owner who reaches the retained-record limit must
wait for old records to expire before creating another operation.

Preserve the coordinator's SQLite volume across restarts. It stores operation
records and the canonical host restrictions, without restoring live tunnels.
Host restrictions remain after sharing is disabled so retired preview URLs
cannot reach management routes. Disable `allow_authenticated` and remove
publishing grants to stop publication
while keeping the domain and control-host configuration explicit.

## Future TCP support

The publisher carries opaque byte streams and selects fixed local targets by
service ID. HTTP is the initial public frontend. A future TCP frontend can reuse
that transport, authorization, TTL, readiness, and connection cleanup.

Plain TCP publication will need public listeners and port allocation because
arbitrary TCP connections do not carry an HTTP hostname. Its endpoints will
include a port. Independent directional shutdown also needs explicit transport
support for protocols that require it. This release does not add public TCP
listeners; its HTTP Upgrade connections already carry opaque application bytes.
