# Self-hosting guide

This guide tells you how to install and operate tunneler. It starts from first
principles. If you only want the Azure procedure, go to
[Azure Kubernetes Service setup](#5-azure-kubernetes-service-setup).

## Contents

- [**Azure Kubernetes Service setup**](#5-azure-kubernetes-service-setup) — the main procedure
- [1. How tunneler works](#1-how-tunneler-works)
- [2. Before you start](#2-before-you-start)
- [3. The Entra app registration](#3-the-entra-app-registration)
- [4. The coordinator](#4-the-coordinator)
- [5. Azure Kubernetes Service setup](#5-azure-kubernetes-service-setup)
- [6. Grants: who can reach what](#6-grants-who-can-reach-what)
- [7. The client](#7-the-client)
- [8. Operation](#8-operation)
- [9. Local development](#9-local-development)

## 1. How tunneler works

Tunneler gives people access to databases that run inside Kubernetes
clusters. The person does not get a shared password. The person gets a
temporary account in their own name, and tunneler records everything that
the account does.

Tunneler has three parts.

- The **coordinator** is one central server. It identifies people, decides
  what they can reach, and carries their database traffic. It keeps its state
  in one SQLite file.
- An **exit node** runs inside each cluster. It connects out to the
  coordinator and keeps that connection open. When the coordinator needs a
  connection into the cluster, the exit node makes it.
- The **client** is the `tunneler` command on a laptop. It opens a local
  port that a database tool connects to.

A database connection goes: database tool → client → coordinator → exit node
→ database. The coordinator reads the Postgres protocol in the middle. It
makes sure that the person logs in only as their temporary account, and it
records each SQL statement.

Three facts explain most of the design.

**Exit nodes make all the connections.** A cluster needs no open port. An
exit node dials the coordinator, and the coordinator asks it for connections
over that link.

**The coordinator has no list of clusters.** An exit node presents a token
that its own Kubernetes cluster issued. The coordinator makes sure that the
token comes from a cluster it trusts, and then it accepts the cluster name
that the exit node gives. The first cluster to use a name owns that name.
When you add a cluster, you change nothing on the coordinator.

**Services register themselves.** A namespace that owns a database creates a
`TunnelService` resource next to it. The exit node in that cluster finds the
resource and tells the coordinator about the service. The resource holds no
password. It holds a reference to a Secret, or to a Key Vault secret.

A **session** is one temporary account. When a person connects, the
coordinator asks the exit node to create a database role with a random
password and an expiry time. When the person disconnects, or an admin revokes
the session, or the session expires, the exit node removes the role. If the
exit node is down at that time, the coordinator remembers the removal and
does it later. The database also refuses the role after its expiry time.

## 2. Before you start

You need these items.

- A Microsoft Entra tenant, and permission to create an app registration in
  it.
- One place to run the coordinator container, with a public DNS name and a
  TLS certificate. Any host that runs containers is sufficient. The
  coordinator needs one persistent disk for its SQLite file.
- A load balancer or ingress in front of the coordinator that passes
  WebSocket connections. Most do this by default.
- One or more AKS clusters with the OIDC issuer feature enabled.
- In each cluster, a Postgres database and an administrative role for
  tunneler (see [section 5.4](#54-prepare-the-postgres-database)).
- The `az` and `kubectl` commands.

The container image is `ghcr.io/mtsaas/tunneler:latest`. One image contains
all three parts.

## 3. The Entra app registration

The coordinator uses one Entra app registration to identify people. The
client uses the same app registration to sign people in. Do this procedure
once.

1. Create a single-tenant app registration:

   ```bash
   az ad app create --display-name tunneler --sign-in-audience AzureADMyOrg --query appId -o tsv
   ```

   Keep the `appId` that the command prints. This guide calls it `$APP`.

2. Let the client sign in with the device code flow. A command line tool
   cannot keep a client secret, so the app must accept public clients:

   ```bash
   az ad app update --id $APP --is-fallback-public-client true
   ```

3. Make Entra put group memberships in ID tokens:

   ```bash
   az ad app update --id $APP --set groupMembershipClaims=SecurityGroup
   ```

   NOTE: If a person is in more than 200 groups, Entra omits the groups from
   the token. The coordinator then refuses the login. For large tenants,
   use `ApplicationGroup` instead and assign the groups to the app.

4. Find your tenant ID:

   ```bash
   az account show --query tenantId -o tsv
   ```

   This guide calls it `$TENANT`.

The coordinator configuration needs two values from this section: the issuer
`https://login.microsoftonline.com/$TENANT/v2.0` and the client ID `$APP`.

## 4. The coordinator

### 4.1 The configuration file

The coordinator reads one JSON file. This is a complete example for
production:

```json
{
  "listen": ":8443",
  "database": "/var/lib/tunneler/tunneler.db",
  "tls": {"cert_file": "/etc/tunneler/tls/tls.crt", "key_file": "/etc/tunneler/tls/tls.key"},
  "session_ttl": "8h",
  "exit_issuers": ["https://*.oic.prod-aks.azure.com/<tenant-id>/*/"],
  "exit_subject": "system:serviceaccount:tunneler:tunneler-exit",
  "oidc": {
    "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
    "client_id": "<app-id>"
  },
  "admins": ["<group-id>"],
  "grants": [
    {"group": "<group-id>", "labels": {"cluster": "prod", "kind": "postgres"}, "roles": ["readonly"]}
  ]
}
```

Each key has one purpose.

| Key | Purpose |
|---|---|
| `listen` | The address and port to serve on. |
| `database` | The SQLite file that holds sessions and cluster names. Put it on a persistent disk. |
| `tls` | The certificate and key. If you omit `tls`, the coordinator serves plain HTTP. Do that only behind a proxy that terminates TLS. |
| `session_ttl` | How long a session and its account live. The default is `8h`. |
| `exit_issuers` | Patterns for the token issuers of clusters that you trust. See [section 5.2](#52-find-the-issuer-url). |
| `exit_audience` | The audience that exit node tokens must carry. The default is `tunneler`. |
| `exit_subject` | The only Kubernetes service account that an exit node can run as. |
| `exit_issuer_ca_file` | A CA bundle for issuers with private certificates. AKS does not need it. |
| `oidc` | The identity provider from [section 3](#3-the-entra-app-registration). |
| `admins` | Groups or people who can see and revoke all sessions. |
| `grants` | Who can reach what. See [section 6](#6-grants-who-can-reach-what). |

The `exit_issuers` value is the important one for Azure. Every AKS cluster in
one tenant has an issuer URL of the form
`https://<region>.oic.prod-aks.azure.com/<tenant-id>/<cluster-id>/`. The
pattern above matches all of them. Azure sets the tenant ID in that URL, so
a cluster in a different tenant cannot match.

### 4.2 Run the coordinator

You can run the coordinator in Kubernetes or as one container. Use the
first procedure if you have a cluster for it.

**In Kubernetes, with Helm.** The chart creates a StatefulSet with a
persistent volume, and a Service. The coordinator serves plain HTTP in the
cluster, and your ingress terminates TLS.

1. Write a file `coordinator-values.yaml`. The `config` key holds the
   configuration from section 4.1, without `listen`, `database`, and `tls`:

   ```yaml
   config:
     exit_issuers: ["https://*.oic.prod-aks.azure.com/<tenant-id>/*/"]
     oidc:
       issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
       client_id: <app-id>
     admins: ["<group-id>"]
     grants:
       - group: <group-id>
         labels: {cluster: prod, kind: postgres}
         roles: [readonly]
   ingress:
     enabled: true
     className: nginx
     host: tunneler.example.com
     tlsSecretName: tunneler-tls
   ```

2. Install the chart:

   ```bash
   helm upgrade --install tunneler-coordinator oci://ghcr.io/mtsaas/charts/tunneler-coordinator \
     --version <version> --namespace tunneler --create-namespace \
     --values coordinator-values.yaml
   ```

   If you use a service mesh gateway, leave `ingress.enabled` off. Route your
   gateway to the Service `tunneler-coordinator`, port 8443.

**As one container.**

1. Put the configuration file, the certificate, and the key on the host.

2. Start the container. Mount the configuration, the TLS files, and a
   persistent directory for the database:

   ```bash
   docker run -d --name tunneler-coordinator -p 8443:8443 \
     -v /srv/tunneler/config.json:/etc/tunneler/config.json:ro \
     -v /srv/tunneler/tls:/etc/tunneler/tls:ro \
     -v /srv/tunneler/data:/var/lib/tunneler \
     ghcr.io/mtsaas/tunneler:latest start coordinator --config /etc/tunneler/config.json
   ```

3. Read the log. The coordinator writes JSON lines to standard output. Make
   sure that you see `coordinator listening`.

4. Point a DNS name at the host. This guide calls it
   `https://tunneler.example.com`.

The coordinator writes an audit trail to the same log. Audit lines have
`"audit":true`. Send the log to your log system, and filter on that field.

If the coordinator restarts, sessions continue. Open connections close, and
the client opens new ones.

## 5. Azure Kubernetes Service setup

Do this procedure for each AKS cluster. Nothing in this procedure touches the
coordinator or the Entra app registration.

### 5.1 Enable the OIDC issuer

Each AKS cluster can issue tokens for its pods and publish the public keys
for those tokens. The coordinator uses those keys.

1. Enable the feature on the cluster:

   ```bash
   az aks update -g $RG -n $CLUSTER --enable-oidc-issuer
   ```

   If you will read credentials from Key Vault, also add
   `--enable-workload-identity`.

### 5.2 Find the issuer URL

1. Show the issuer URL:

   ```bash
   az aks show -g $RG -n $CLUSTER --query oidcIssuerProfile.issuerUrl -o tsv
   ```

2. Make sure that the URL matches the `exit_issuers` pattern in the
   coordinator configuration. The tenant ID in the URL must be your tenant.

### 5.3 Install the exit node

The exit node runs as a Deployment with two replicas. It gets a projected
service account token with the audience `tunneler`. Kubernetes issues that
token and rotates it. The exit node presents it to the coordinator.

1. Install the chart. It contains the `TunnelService` custom resource
   definition. Set `server` to the coordinator URL. Set `cluster` to the name
   of this cluster, for example `prod`:

   ```bash
   helm upgrade --install tunneler-exit oci://ghcr.io/mtsaas/charts/tunneler-exit \
     --version <version> --namespace tunneler --create-namespace \
     --set server=https://tunneler.example.com --set cluster=prod
   ```

   CAUTION: Use each cluster name once. The coordinator binds a name to the
   first cluster that presents it, and refuses the name to other clusters.

   NOTE: The coordinator configuration names the service account
   `system:serviceaccount:tunneler:tunneler-exit` in `exit_subject`. If you
   install into a different namespace, change `exit_subject` to match.

2. Make sure that the exit node connected. Its log must contain
   `connected to coordinator`:

   ```bash
   kubectl -n tunneler logs deployment/tunneler-exit
   ```

3. Make sure that the coordinator accepted it. The coordinator log must
   contain `exit node connected` with your cluster name.

If the coordinator log contains `exit node rejected`, read the `err` field.
It names the issuer, the subject, or the bound cluster that did not match.

### 5.4 Prepare the Postgres database

The exit node needs an administrative role on each database. That role
creates and removes the temporary accounts. It does not need superuser.

1. Connect to the database as a superuser.

2. Create the role:

   ```sql
   CREATE ROLE tunneler_admin LOGIN PASSWORD '<password>' CREATEROLE;
   ```

3. For each role that people can receive, give `tunneler_admin` the right to
   grant it:

   ```sql
   GRANT readonly TO tunneler_admin WITH ADMIN OPTION;
   GRANT readwrite TO tunneler_admin WITH ADMIN OPTION;
   ```

4. Write the connection string for `tunneler_admin`:

   ```
   postgres://tunneler_admin:<password>@<host>:5432/<database>?sslmode=require
   ```

   The database in this string is the only database that sessions can use.
   For a server with more databases, register one `TunnelService` per
   database.

### 5.5 Store the connection string

Put the connection string where the `TunnelService` can refer to it. There
are two options.

**Option A: a Kubernetes Secret.** Create the Secret in the namespace of the
database:

```bash
kubectl -n shop create secret generic orders-db-tunneler --from-literal=dsn='postgres://...'
```

Then let the exit node read that one Secret. Create a Role and a RoleBinding
in the same namespace. The `resourceNames` field limits the Role to this
Secret only:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: tunneler-read-dsn, namespace: shop}
rules:
  - apiGroups: [""]
    resources: [secrets]
    resourceNames: [orders-db-tunneler]
    verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: tunneler-read-dsn, namespace: shop}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: tunneler-read-dsn}
subjects:
  - {kind: ServiceAccount, name: tunneler-exit, namespace: tunneler}
```

On a development cluster, you can skip the Role and the RoleBinding. Install
the exit node chart with `--set secretAccess=cluster`. The exit node can then
read every Secret in the cluster.

CAUTION: Do not use `secretAccess=cluster` on a production cluster. It gives
the exit node access to all Secrets.

**Option B: Azure Key Vault.** The exit node reads the secret through a
workload identity. This is the better option for credentials that Terraform
manages.

1. Create a managed identity for the exit node:

   ```bash
   az identity create -g $RG -n tunneler-exit
   ```

2. Add a federated credential for the exit node service account:

   ```bash
   az identity federated-credential create -g $RG --identity-name tunneler-exit \
     --name tunneler-exit --issuer $ISSUER_URL \
     --subject system:serviceaccount:tunneler:tunneler-exit \
     --audience api://AzureADTokenExchange
   ```

3. Give the identity the `Key Vault Secrets User` role on the secret:

   ```bash
   az role assignment create --role "Key Vault Secrets User" \
     --assignee-object-id $(az identity show -g $RG -n tunneler-exit --query principalId -o tsv) \
     --assignee-principal-type ServicePrincipal \
     --scope /subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.KeyVault/vaults/$VAULT/secrets/tunneler-db-uri
   ```

4. Give the client ID of the identity to the chart. The chart adds the
   workload identity annotation and label:

   ```bash
   helm upgrade tunneler-exit oci://ghcr.io/mtsaas/charts/tunneler-exit --reuse-values \
     --set workloadIdentity.clientId=$(az identity show -g $RG -n tunneler-exit --query clientId -o tsv)
   ```

### 5.6 Register the service

1. Create a `TunnelService` in the namespace of the database:

   ```yaml
   apiVersion: tunneler.marconet.com/v1alpha1
   kind: TunnelService
   metadata:
     name: postgres
     namespace: shop
   spec:
     kind: postgres
     credentials:
       dsnRef:
         kubernetesSecret: {name: orders-db-tunneler, key: dsn}
     grantableRoles: [readonly, readwrite]
     labels:
       team: shop
   ```

   For Key Vault, replace `kubernetesSecret` with
   `azureKeyVault: {vaultUri: https://<vault>.vault.azure.net, secretName: tunneler-db-uri}`.

2. Make sure that the service is ready:

   ```bash
   kubectl -n shop get tunnelservice
   ```

   The `READY` column must show `True`. If it shows `False`, the `REASON`
   column tells you why. `CredentialsInvalid` means that the exit node
   cannot read the Secret. `Unreachable` means that the connection string
   does not work.

The coordinator knows this service as `shop-postgres`. It has the labels
`cluster`, `kind`, `name`, `namespace`, and `team`. When you delete the
`TunnelService`, the service disappears from the coordinator.

`grantableRoles` is a limit. The coordinator can give a person only roles
from this list. A grant that names another role fails.

## 6. Grants: who can reach what

A grant connects a group, or one person, to a set of services. It selects
services by labels. A grant reaches every service that has all of the
labels in the grant.

```json
{"group": "<group-id>", "labels": {"cluster": "prod", "team": "shop"}, "roles": ["readonly"]}
```

This grant reaches every service on `prod` with the label `team: shop`. A
person who uses it gets the database role `readonly`.

Some rules:

- A grant names a `group` by its Entra object ID, or a `user` by object ID
  or by email address. A grant has one or the other.
- A grant with only `"cluster": "prod"` reaches everything on `prod`.
- A person with several grants gets the roles from all grants that reach the
  service.
- A grant with no `roles` gives an account with no privileges beyond
  `PUBLIC`.
- Every service has the labels `cluster`, `kind`, `name`, and `namespace`.
  The exit node sets them. A `TunnelService` cannot set them.

The coordinator reads the configuration file again when the file changes.
A restart is not necessary, and open connections stay open. New grants apply
to the next request. If a person loses access, the coordinator revokes their
session at their next connection.

The keys `listen`, `database`, `tls`, `oidc`, and `exit_issuer_ca_file` are
the exception. A change to those applies after a restart. The log names them.

## 7. The client

Each person installs the `tunneler` command. See
[Installation](../README.md#installation) in the README.

1. Point the client at the coordinator:

   ```bash
   tunneler config --server https://tunneler.example.com
   ```

2. Sign in. The command shows a URL and a code:

   ```bash
   tunneler auth login
   ```

3. Make sure that the coordinator knows you:

   ```bash
   tunneler auth status
   ```

   The output shows the token, your groups, the grants that apply to you,
   and the services that you can reach. If the groups list is empty, the app
   registration does not emit groups. See [section 3](#3-the-entra-app-registration).

4. Connect to a service. Give labels that match exactly one service:

   ```bash
   tunneler connect cluster=prod team=shop
   ```

   If the labels match more than one service, the command lists them and
   asks you to select one. With no labels, it lists every service that you
   can reach.

The command prints a host, a port, a user, and a password. Give them to your
database tool. Press Ctrl-C to disconnect. The coordinator then removes the
account. The port for one service is the same each time, so a saved
connection in a database tool continues to work. Only the user and the
password change.

To run one command, put it after `--`. The command gets the connection in
its environment (`PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`,
and `DATABASE_URL`). When the command stops, the coordinator removes the
account:

```bash
tunneler connect cluster=prod team=shop -- psql
```

### Scripts and agents

The client has a stable contract for programs. `tunneler help output` and
`tunneler help exit-codes` give the same information.

- `--output json` makes each command write its result to stdout as JSON.
  Errors go to stderr as `{"error", "code", "matches"}`. The command does not
  ask questions.
- `tunneler connect <labels> -- <command>` is the best way to run one
  database command. It shows no credentials.
- The exit status tells you the type of failure:

  | Status | Meaning |
  |---|---|
  | 0 | Success |
  | 1 | Other failure |
  | 2 | Incorrect flags or arguments |
  | 3 | Not logged in. A person must run `tunneler auth login` |
  | 4 | Access denied, or no service matches |
  | 5 | The labels match more than one service. The error lists them |
  | 6 | The service or the coordinator is not available |

- `TUNNELER_SERVER` sets the coordinator without a configuration file.

## 8. Operation

### Sessions

An admin can list all sessions and end any of them:

```bash
tunneler sessions list
tunneler sessions revoke <id>
```

A revoked session loses its connections at once. The exit node removes the
account.

### A rebuilt cluster

A rebuilt AKS cluster has a new issuer URL. The coordinator refuses its exit
nodes, because the old cluster owns the name. An admin releases the name:

```bash
tunneler clusters forget prod
```

The next cluster to present the name `prod` then owns it.

### Removal of accounts after a fault

Temporary accounts are removed by three separate mechanisms.

1. The coordinator records a session before it creates the account. After a
   restart, it revokes sessions that expired while it was down. If the exit
   node is not reachable, it keeps the removal as pending and retries when
   an exit node of that cluster connects.
2. The exit node removes accounts that are past their expiry time. It does
   this at start, every hour, and before it creates an account.
3. Postgres refuses a login after the account's `VALID UNTIL` time.

In the worst case, an account that cannot log in remains for less than one
hour after its expiry time.

### The audit trail

The coordinator log records each session, each connection, and each SQL
statement. Each record names the person and the session. Filter the log on
`"audit":true`.

## 9. Local development

For a laptop, the coordinator can accept exit nodes without a token, and the
exit node can read services from a file.

1. Write a coordinator configuration with these keys, and no `tls`:

   ```json
   {
     "listen": "127.0.0.1:8443",
     "database": "tunneler.db",
     "insecure_exit_auth": true,
     "oidc": {"issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0", "client_id": "<app-id>"},
     "grants": [{"user": "you@example.com", "labels": {"cluster": "dev"}, "roles": ["pg_read_all_data"]}]
   }
   ```

   CAUTION: Do not use `insecure_exit_auth` outside a laptop. With it, any
   exit node is accepted as any cluster.

2. Start a Postgres and the coordinator:

   ```bash
   docker run --rm -d -p 5432:5432 -e POSTGRES_PASSWORD=pw postgres:17
   tunneler start coordinator --config coordinator.json
   ```

3. Write `exit.json`:

   ```json
   {"services": [{"name": "pg", "kind": "postgres", "dsn": "postgres://postgres:pw@localhost:5432/postgres?sslmode=disable", "roles": ["pg_read_all_data"]}]}
   ```

4. Start the exit node:

   ```bash
   tunneler start exit --cluster=dev --server http://localhost:8443 --config exit.json
   ```

5. Use the client as in [section 7](#7-the-client). Use
   `http://localhost:8443` as the server.

The test suite has two end-to-end tests. `TUNNELER_TEST_DSN` runs the
Postgres tests. `TUNNELER_KIND=1` runs the exit node against a real
Kubernetes issuer in a kind cluster:

```bash
TUNNELER_KIND=1 go test -count=1 -timeout 15m ./e2e/
```
