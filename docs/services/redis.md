# Redis

This guide shows how to offer a Redis service through tunneler and how to
connect to it. Tunneler must be installed first. See the [self-hosting
guide](../self-hosting.md) and the [service overview](README.md).

## How it works

Each session gets a temporary Redis ACL user. The exit node creates that user
on the Redis data nodes. A Redis client connects through a local port and
authenticates as the temporary user. Redis checks the password and the user's
command, key, and channel permissions. The coordinator records each complete
command before it forwards the command to Redis.

The administrative Redis credential stays with the exit node. The client
receives only the temporary user's name and password. When the session ends,
the exit node removes the user.

## Prepare Redis

Redis 7 or later is required. Tunneler supports database 0 only. Redis ACLs
cannot limit a user to one numbered database, so tunneler denies commands
that change databases.

Create the same administrative Redis user on every data node. Give it a
password and these command permissions: `PING`, `INFO`, `ACL SETUSER`,
`ACL DELUSER`, and `ACL USERS`. For Cluster, it also needs `CLUSTER SHARDS`.
If Sentinel requires authentication, give it `SENTINEL GET-MASTER-ADDR-BY-NAME`
and `SENTINEL REPLICAS` on the Sentinel nodes.

Use the administrative user's credentials in a URL with this form:

```text
rediss://tunneler_admin:<password>@cache.shop.svc:6379/0
```

Encode reserved characters in the URL password, such as `@` as `%40`.
Use `rediss://` when the exit node must use TLS to reach Redis. Use
`redis://` only when plain TCP is appropriate. With `rediss://`, the exit node
must trust the Redis certificate. The certificate must be valid for the
address that the exit node uses. For Cluster, this includes each advertised
node address.

## Store the administrative URL

Store the URL in a Kubernetes Secret in the service's namespace. The example
below creates a Secret named `cache-tunneler` with a key named `url`:

```bash
kubectl -n shop create secret generic cache-tunneler \
  --from-literal=url='rediss://tunneler_admin:<password>@cache.shop.svc:6379/0'
```

If the exit node uses namespace-scoped Secret access, give its service account
permission to read this Secret:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: tunneler-read-cache-url, namespace: shop}
rules:
  - apiGroups: [""]
    resources: [secrets]
    resourceNames: [cache-tunneler]
    verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: tunneler-read-cache-url, namespace: shop}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: tunneler-read-cache-url}
subjects:
  - {kind: ServiceAccount, name: tunneler-exit, namespace: tunneler}
```

For other Secret access modes or Azure Key Vault, see [Store the connection
string](postgres.md#3-store-the-connection-string). Use the Redis URL and
Secret name from this page in those steps.

## Register the service

Create this `TunnelService` in the same namespace as the Secret:

```yaml
apiVersion: tunneler.marconet.com/v1alpha1
kind: TunnelService
metadata:
  name: cache
  namespace: shop
spec:
  kind: redis
  credentials:
    dsnRef:
      kubernetesSecret:
        name: cache-tunneler
        key: url
  grantableRoles: [reader, writer]
  redis:
    mode: standalone
    aclProfiles:
      reader: ["+get", "~shop:*"]
      writer: ["+get", "+set", "~shop:*"]
  labels:
    team: shop
```

The `aclProfiles` field maps each profile name to Redis ACL rules. In this
example, `reader` can read keys named `shop:*`. The `writer` profile can read
and write those keys. Rules can name commands or categories with `+`, key
patterns with `~`, and channel patterns with `&`. Tunneler adds denials for
commands that change server configuration, identity, or database scope.

The `grantableRoles` list limits which profiles a grant can give a person.
See [Roles](README.md#3-roles) for how grants select a service and its
profiles. After creating the resource, make sure that it is ready:

```bash
kubectl -n shop get tunnelservice cache
```

The `READY` column must show `True`. See [Readiness](README.md#4-readiness)
for the meaning of other states.

### Sentinel

For Sentinel, replace `mode: standalone` with the following fields under
`redis`:

```yaml
mode: sentinel
masterName: cache-primary
sentinels: ["sentinel-1.shop.svc:26379", "sentinel-2.shop.svc:26379"]
allowedNodes: ["10.42.0.0/16"]
```

Keep `aclProfiles` in the same `redis` block. The URL in the Secret names a
Redis data node, not a Sentinel. The exit node asks Sentinel for the current
primary and discovers its replicas. `allowedNodes` lists the data-node
addresses that the exit node can use. It accepts CIDRs or exact hostnames.

Sentinel uses the administrative URL's credentials if it requires
authentication. Sentinel discovery uses plain TCP. A `rediss://` URL secures
connections to the Redis data nodes, not to Sentinel. The data-node addresses
that Sentinel returns must accept TLS on their advertised ports.

### Cluster

For Redis Cluster, replace `mode: standalone` with `mode: cluster` and add
`allowedNodes` under `redis`:

```yaml
mode: cluster
allowedNodes: ["10.42.0.0/16"]
```

Keep `aclProfiles` in the same `redis` block. The URL in the Secret names a
Cluster seed node. The exit node discovers the other nodes and checks each
address against `allowedNodes`. With `rediss://`, it connects to the nodes'
advertised TLS ports when Redis supplies them.

Cluster clients need ACL permission to discover topology. Add
`+cluster|slots`, `+cluster|shards`, and `+command` to each profile used by a
Cluster client, along with its data-command and key rules.

## Connect

Connect to the registered service with its cluster and service name:

```console
tunneler connect cluster=prod name=shop/cache
```

The command prints a local `redis://` URL and a `redis-cli` example. The
client connects to this local URL, even when the exit node uses `rediss://`
to connect to Redis. In Cluster mode, tunneler opens one local port per node
and shows a `redis-cli -c` example.

To start `redis-cli` directly, put it after `--`:

```console
tunneler connect cluster=prod name=shop/cache -- redis-cli
```

Tunneler passes the local address, port, and temporary username to
`redis-cli`. It also passes `-c` for Cluster. Other commands after `--`
receive `REDIS_URL` and `REDISCLI_AUTH` in their environment.

## Audit and limits

The coordinator records command names and arguments. It redacts passwords
in `AUTH` and `HELLO AUTH`, but it does not redact data values. Treat the
audit sink as sensitive.

A tunnel connection must authenticate as its temporary user before it sends
data commands. It cannot change to another Redis user during that
connection. Redis ACLs enforce the user's command, key, and channel rules.

Redis ACL users have no built-in expiry. Tunneler removes each temporary
user when its session ends and reaps expired users when the exit node runs.
If all exit nodes are down at expiry, a direct Redis connection can still
use the temporary credentials until cleanup resumes.

Cluster sessions require RESP2. Redis Pub/Sub is not supported through
Cluster sessions. Start a new session after a Cluster topology change.
