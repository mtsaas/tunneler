# Postgres

This document tells you how to offer a Postgres database through tunneler,
and how people connect to it. Tunneler must be installed first. See the
[self-hosting guide](../self-hosting.md). For the ideas that all kinds of
service share, see [Services](README.md).

## Contents

- [1. How it works](#1-how-it-works)
- [2. Prepare the database](#2-prepare-the-database)
- [3. Store the connection string](#3-store-the-connection-string)
- [4. Register the database](#4-register-the-database)
- [5. Connect](#5-connect)
- [6. The audit trail](#6-the-audit-trail)
- [7. Problems and their causes](#7-problems-and-their-causes)
- [8. Limits](#8-limits)

## 1. How it works

```
database tool → tunneler connect → coordinator → exit node → Postgres
```

**Each person gets a temporary account.** When a person connects, the exit
node creates a database role with a random password and an expiry time. The
role is a member of the roles that the grants of the person give. The person
never sees a shared password.

**The coordinator reads the Postgres protocol.** It lets the person log in as
their temporary account only, and into one database only. It records each
SQL statement, and refuses what it cannot record in full.

**The account goes away.** When the person disconnects, when an admin revokes
the session, or when the session expires, the exit node removes the role. It
also drops the objects that the person made, such as tables, functions, and
views. The exit node does not keep them or give them to another role: a
function or a view carries the privileges of its owner, so an object left in
the hands of a more privileged role would let a later session act with those
privileges. If the exit node is down at that time, the coordinator does the
removal later. Postgres also refuses the role after its expiry time.

**The administrative credential stays in the cluster.** The exit node reads
it from a Kubernetes Secret or from Azure Key Vault. The coordinator does not
have it.

## 2. Prepare the database

The exit node needs an administrative role on each database. That role
creates and removes the temporary accounts. Give it `CREATEROLE` and the
right to grant the roles that people receive, and nothing more. It must not
be a superuser. The exit node runs some cleanup as this role, so the fewer
privileges it holds, the less a mistake or a flaw can reach.

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

   The string must be complete. It must be a URL, and it must give the
   host, the user, and the password. The exit node adds nothing from its
   own environment or files, such as `PGPASSWORD` or `~/.pgpass`. After the
   `?`, the string can set only `sslmode` and `connect_timeout`. Encode
   special characters in the password, for example `@` as `%40`.

## 3. Store the connection string

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

The Role is also what lets the `TunnelService` resources of the namespace
use the Secret. A person who can create a `TunnelService` there can name
any key of the Secret, even if that person cannot read the Secret. The exit
node does not show the value of the key. But it offers a service for any
key that holds a complete connection string, and the status of that
service can show the host, the port, the user, and the database of the
string. So give the exit node a Secret that holds only the connection
string. Do not give it a Secret with other keys, such as one that a
database operator makes.

On a development cluster, you can skip the Role and the RoleBinding. Install
the exit node chart with `--set secretAccess=cluster`. The exit node can then
read every Secret in the cluster.

CAUTION: Do not use `secretAccess=cluster` on a production cluster. It gives
the exit node access to all Secrets. Then a person who can create a
`TunnelService` in a namespace can use every Secret of that namespace.

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

5. Let the namespace use the secret. The identity can read the secrets of
   all namespaces, so Azure cannot keep a namespace to its own secret. The
   exit node does this instead: a namespace can use only the secrets that
   you list for it.

   ```bash
   helm upgrade tunneler-exit oci://ghcr.io/mtsaas/charts/tunneler-exit --reuse-values \
     --set 'workloadIdentity.keyVaultSecrets.shop={https://<vault>.vault.azure.net/secrets/tunneler-db-uri}'
   ```

   A `TunnelService` that names a secret which is not listed for its
   namespace shows `InvalidSpec`. The exit node does not read that secret.
   If you upgrade from version 0.4.0 or earlier, see
   [Upgrades](../self-hosting.md#upgrades).

## 4. Register the database

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
   The secret must be listed for the namespace. See step 5 of option B.

2. Make sure that the service is ready:

   ```bash
   kubectl -n shop get tunnelservice
   ```

   The `READY` column must show `True`. If it shows `False`, the `REASON`
   column tells you why. `CredentialsInvalid` means that the exit node
   cannot read the Secret. `InvalidSpec` means that the resource or the
   connection string is not correct, for example a Key Vault secret that is
   not listed for the namespace, and the message says why. The message
   does not quote the connection string. Compare the string with the form
   in step 4 of [section 2](#2-prepare-the-database). `Unreachable` means
   that the connection string does not work.

The coordinator knows this service as `shop-postgres`. It has the labels
`cluster`, `kind`, `name`, `namespace`, and `team`. When you delete the
`TunnelService`, the service disappears from the coordinator.

`grantableRoles` is a limit. The coordinator can give a person only roles
from this list. A grant that names another role fails.

## 5. Connect

Each person connects with the labels of the database:

```bash
tunneler connect cluster=prod team=shop
```

The command prints a host, a port, a database, a user, and a password. Give
them to your database tool. The command continues to run, and carries the
connections. Press Ctrl-C to disconnect. The coordinator then removes the
account.

The port for one database is the same each time. A saved connection in a
database tool continues to work, and only the user and the password change.
Use `--port` to select a different port.

To run one command, put it after `--`. The command gets the connection in
its environment (`PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`,
and `DATABASE_URL`). No credential is shown. When the command stops, the
coordinator removes the account:

```bash
tunneler connect cluster=prod team=shop -- psql
tunneler connect name=shop-postgres -- pg_dump --schema-only -f schema.sql
```

Connect with `sslmode=disable`. The connection from your computer to the
coordinator is encrypted by tunneler. The connection from the exit node to
Postgres uses the `sslmode` of the administrative connection string.

## 6. The audit trail

The coordinator writes these records. Each has the
[fields that all kinds share](README.md#6-the-audit-trail), with
`"kind":"postgres"`. Each also has `session`, the ID of the session, and
`account`, the temporary database account:

| Message | When |
|---|---|
| `session created` | The account exists. The record lists the roles and the expiry time |
| `connection opened`, `connection closed` | For each connection of the database tool |
| `query` | For each SQL statement, with the whole text in `sql` |
| `session revoked` | The session ended. The record gives the reason |
| `access denied` | No grant gives the person access |

```json
{"msg":"query","audit":true,"user":"alice@example.com","subject":"...","cluster":"prod",
 "service":"shop-postgres","kind":"postgres","session":"K3Q2XB7HTLW5",
 "account":"tnl_alice_example_com_x7k2p9qa","sql":"select * from orders"}
```

The coordinator refuses what it cannot record in full: a statement longer
than 1 MiB, and a fast-path function call. The database tool gets an error,
and the connection closes. The `connection closed` record gives the reason
in `err`. See [Limits](#8-limits).

## 7. Problems and their causes

| What you see | Cause | What to do |
|---|---|---|
| `tunneler services list` shows `unreachable` | The exit node cannot log in with the administrative connection string | Read the reason in the list. Correct the Secret or the database role |
| The `TunnelService` shows `CredentialsInvalid` | The exit node cannot read the Secret or the Key Vault secret | Add the Role and the RoleBinding, or the Key Vault role assignment |
| The `TunnelService` shows `CredentialsInvalid`: `no answer within 10s` | Key Vault or Entra ID did not answer in time. The exit node stops waiting, so that the other resources are not held up | Make sure that the exit node can reach the vault and Entra ID. The exit node tries again within 5 minutes |
| The `TunnelService` shows `InvalidSpec`, and the message names a Key Vault secret | The secret is not listed for the namespace | Add the secret to `workloadIdentity.keyVaultSecrets` for the namespace. The message gives the exact value |
| The `TunnelService` shows `InvalidSpec`: `the dsn must give its own host, user and password` | The connection string does not include one of them. The exit node does not take them from its own environment | Put the complete connection string in the Secret |
| The `TunnelService` shows `InvalidSpec`: `the dsn's query may set only sslmode and connect_timeout` | The connection string sets another parameter after the `?`, such as `passfile` or `sslkey`, which name files on the exit node | Remove the parameter |
| The `TunnelService` shows `InvalidSpec`: `the dsn is not valid: check its port, sslmode and connect_timeout` | The port, `sslmode`, or `connect_timeout` has a value that is not valid. Or the exit node has `PGSERVICE` in its environment | Correct the value. The port is 1 to 65535. `sslmode` is `disable`, `allow`, `prefer`, `require`, `verify-ca`, or `verify-full`. `connect_timeout` is a number of seconds |
| The `TunnelService` shows `InvalidSpec`: `the dsn is not a URL ...` | The connection string has the `key=value` form, or is not a valid URL | Write it as a `postgres://` URL. Encode special characters in the password |
| `provisioning access failed: ... role "x" is not grantable` | A grant gives a role that `grantableRoles` does not list | Add the role to `grantableRoles`, or remove it from the grant |
| `provisioning access failed: ... permission denied to grant role` | The administrative role cannot grant that role | `GRANT x TO tunneler_admin WITH ADMIN OPTION` |
| `this session only permits logging in as ...` | The database tool used a different user | Use the user that `tunneler connect` printed |
| `this session only permits database ...` | The database tool asked for a different database | Use the database that `tunneler connect` printed |
| `this session only permits statements of up to 1 MiB ...` | The database tool sent one statement longer than 1 MiB, for example an `INSERT` of many rows | Send smaller statements, for example fewer rows in each `INSERT`. Or load the rows with `COPY` |
| `this session only permits SQL statements, not fast-path function calls` | The tool uses the large-object functions of libpq or of the JDBC driver, for example `pg_dump` of a database that has large objects | See [Limits](#8-limits) |

## 8. Limits

- One service is one database. For a server with more databases, register
  one `TunnelService` for each database.
- A session is for work that does not outlive it. The exit node drops the
  objects a session made when the account goes away, so a table you want to
  keep must live in a database you reach another way.
- The coordinator records the whole text of each statement. It does not
  record the values of parameters that the database tool sends separately,
  or the rows that a `COPY` sends.
- A statement can be at most 1 MiB long. The coordinator refuses a longer
  statement, because it records each statement in full. The record of a
  long statement is a long line in the coordinator log. Make sure that your
  log system keeps lines of that length, because some split or cut them.
- The coordinator refuses fast-path function calls. Such a call runs a
  function outside of a SQL statement, so no statement records it. libpq
  uses these calls for large objects, and so does the JDBC driver for a
  `Blob` or a `Clob`. Thus these do not work: `pg_dump` of a database that
  has large objects, `pg_restore` of large objects into a database,
  `\lo_import`, `\lo_export`, and `\lo_unlink` in psql, and the large
  objects of psycopg2 and of JDBC. Use `pg_dump -B`, which leaves out large
  objects. Or use the SQL functions for large objects, such as `lo_get`,
  `lo_put`, and `lo_from_bytea`.
- If the log of the Postgres server includes statements that create roles,
  that log contains the temporary passwords.
- The connection string of a `TunnelService` cannot give a CA certificate
  or a client certificate. With `sslmode=verify-ca` or `verify-full`, the
  certificate of the server must come from a public CA.
