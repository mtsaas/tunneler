# Redis services

Redis services use temporary Redis ACL users. The exit node creates the user
on each data node; Redis checks its password and command, key, and channel
permissions. The coordinator audits each complete command before forwarding
it. `AUTH` remains end-to-end, but a tunnel connection cannot switch to a
different Redis username: Redis ACL rules do not constrain `AUTH` with another
user's valid credentials.

Redis 7 or later is required. The `default` ACL user must be off on every
data node. Only database 0 is supported, because Redis ACLs do not isolate
numbered databases. A Redis ACL account has no native expiry: tunneler
revokes it when the session ends and reaps expired accounts on the exit node,
but a direct Redis connection may continue using it if every exit node is
down at expiry.

## Register a service

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

The Secret value is an administrative URL such as
`rediss://tunneler_admin:password@cache.shop.svc:6379/0`. Use `redis://`
only when plain TCP from the exit node to Redis is appropriate. The URL
must name a user with permission to inspect topology and manage ACL users.

Profiles contain additive Redis ACL rules: `+` commands or categories, `~`
key patterns, and `&` channel patterns. Each granted profile is a separate
ACL selector, so multiple grants form a union. Tunneler adds mandatory
denials for commands that change server identity, configuration, or database
scope. The service's `grantableRoles` list limits which profile names the
coordinator may request.

For Sentinel, set `mode: sentinel`, `masterName`, `sentinels` as `host:port`
addresses, and `allowedNodes` as CIDRs or exact hostnames for the Redis data
nodes. The exit node discovers the current primary for each new connection
and provisions the temporary user on the primary and its replicas. Sentinel
authentication uses the administrative URL's credentials if the Sentinel
requires authentication.

For Redis Cluster, set `mode: cluster` and `allowedNodes`. The exit node
discovers all advertised nodes and verifies that every slot is covered.
`CLUSTER SLOTS`, `CLUSTER SHARDS`, `MOVED`, and `ASK` replies are rewritten to
the CLI's local ports. Cluster clients must use RESP2 and have ACL permission
for topology discovery, typically `+cluster|slots`, `+cluster|shards`, and
`+command` in addition to their data commands. Redis Pub/Sub is not supported
through Cluster sessions. Start a new session after a topology change.

## Connect

```console
tunneler connect cluster=prod name=shop/cache
```

The command prints a local `redis://` URL and a `redis-cli` example. In
Cluster mode it opens one loopback listener per advertised node and prints a
`redis-cli -c` example. Commands after `--` receive `REDIS_URL` and
`REDISCLI_AUTH` in their environment. For `-- redis-cli`, tunneler also passes
the local host, port, temporary ACL user, and (for Cluster) `-c` automatically:

```console
tunneler connect cluster=prod name=shop/cache -- redis-cli
```

The coordinator audits command names
and arguments; passwords in `AUTH` and `HELLO AUTH` are redacted, but data
values are not. Treat the audit sink as sensitive.
