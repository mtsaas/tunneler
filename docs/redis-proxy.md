# Redis service proxy

Redis is a session service in tunneler. The exit node owns the administrative
Redis URL, discovers topology, creates a temporary Redis ACL user on each
data node, and dials raw data connections. The coordinator audits complete
RESP commands before forwarding them. The CLI opens local listeners and
revokes the user when the session ends.

The same session model supports three deployment modes:

| Mode | Exit-node discovery | CLI listeners | Coordinator response handling |
|---|---|---|---|
| Standalone | Configured endpoint | One | Opaque replies |
| Sentinel | Current primary and replicas | One, connected to the current primary | Opaque replies |
| Cluster | `CLUSTER SHARDS`, all advertised nodes and slots | One per node | Rewrites topology and redirects to local ports |

The proxy uses `redcon` for RESP command and Cluster reply parsing, and
`go-redis` for the exit node's administrative commands. It does not implement
Redis authorization. The temporary user's ACL selectors determine which
commands, keys, and channels Redis permits. Redis itself checks the password.

There are two transport boundaries that Redis ACLs cannot express. First,
`AUTH` and `HELLO AUTH` can switch to any user whose credentials the client
knows, regardless of the current user's command ACL. The proxy therefore
binds these handshakes to the temporary username, so a tunnel session cannot
become a different Redis identity. Second, Cluster topology replies and
`MOVED`/`ASK` must contain the CLI's loopback addresses, not the service's
internal addresses. The proxy rewrites those replies and refuses unsupported
Cluster response modes.

Redis ACLs are not scoped to numbered databases. Services therefore require
database 0. Mandatory ACL removals deny `SELECT` and other database-changing
commands. Every data node must have its `default` user off. This means a new
data connection can do nothing until Redis accepts the temporary user's
credentials.

Cluster node selection crosses the coordinator-to-exit protocol as a node ID,
not as a caller-supplied address. The exit resolves that ID against its
validated, allowlisted topology. The coordinator accepts local port mappings
only for nodes advertised by the exit. The exit also advertises a fingerprint
of each Redis node's run ID. A new connection revokes its session if Redis
restarted or the advertised topology changed, because the temporary ACL user
may no longer exist on that server.

Redis ACL users have no native expiry. The coordinator stops forwarding at
session expiry, while the exit node deletes the user on revocation, schedules
a local timer, and reaps expired tunnel-owned names after restart. Direct
Redis access may outlive expiry if all exit nodes are down; operators should
account for this difference from Postgres's `VALID UNTIL`.

The integration tests start real local Redis processes for standalone,
Sentinel with a primary failover, and a three-primary Redis Cluster. They
verify ACL denial, credential binding, data commands, Cluster topology
translation, and redirects. See [Redis service setup](services/redis.md) for
registration and client instructions.
