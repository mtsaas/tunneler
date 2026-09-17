# tunneler

Identity-aware access to services inside Kubernetes clusters. Users sign in
with Entra, get a temporary Postgres account scoped by their groups, and
connect through a local port; every statement is audited under their name.

```
psql ──▶ tunneler connect ══TLS══▶ coordinator ◀══TLS══ exit node ──▶ postgres
```

One binary, three modes.

## Coordinator

Runs once, centrally. Verifies logins, applies grants, proxies and audits
connections, keeps sessions in SQLite.

```bash
tunneler start coordinator --config coordinator.json
```

```json
{
  "listen": ":8443",
  "database": "/var/lib/tunneler/tunneler.db",
  "tls": {"cert_file": "tls.crt", "key_file": "tls.key"},
  "oidc": {"issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0", "client_id": "<client-id>"},
  "admins": ["<group or user id>"],
  "grants": [
    {"group": "<group id>", "labels": {"cluster": "prod", "kind": "postgres"}, "roles": ["readonly"]},
    {"user": "alice@example.com", "labels": {"cluster": "dev"}, "roles": ["readwrite"]}
  ]
}
```

A grant reaches every service carrying all of its labels. Clusters and
services are never configured here; exit nodes bring them. For local
development add `"insecure_exit_auth": true` and drop `tls`.

## Exit node

Runs in each cluster. Dials out to the coordinator, advertises its services,
provisions accounts on them. Credentials stay in the cluster. Authenticates
with Azure Workload Identity (its managed identity needs the app role
`exit:<cluster>`); see [examples/exit-node.yaml](examples/exit-node.yaml).

```bash
TUNNELER_SERVER=https://tunneler.example.com tunneler start exit --cluster=prod --config exit.json
```

```json
{
  "services": [
    {
      "name": "orders-db",
      "kind": "postgres",
      "dsn": "postgres://admin:$ORDERS_DB_PASSWORD@orders-db.shop.svc:5432/orders?sslmode=require",
      "labels": {"team": "shop"},
      "roles": ["readonly", "readwrite"]
    }
  ]
}
```

Every service also gets the labels `cluster`, `kind` and `name`.

## CLI

```bash
tunneler config --server https://tunneler.example.com
tunneler auth login
tunneler auth status                    # what the IdP said, and what it grants you
tunneler clusters list
tunneler connect cluster=prod team=shop # labels; must match exactly one service
tunneler sessions list
tunneler sessions revoke <id>
```

`connect` prints host, port, user, password and a `psql` command, then
carries connections until Ctrl-C, which revokes the account.

## Development

```bash
docker run --rm -d -p 5432:5432 -e POSTGRES_PASSWORD=pw postgres:17
TUNNELER_TEST_DSN='postgres://postgres:pw@localhost:5432/postgres?sslmode=disable' go test -race ./...
```

`ponytail:` comments mark deliberate simplifications and their upgrade path.
