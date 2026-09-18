# Services

A service is something inside a cluster that people reach through tunneler.
This document tells you how services are offered and how people connect to
them. Each kind of service has its own document:

| Kind | What people get | Document |
|---|---|---|
| `postgres` | A temporary database account, and a local port for a database tool | [Postgres](postgres.md) |
| `kubernetes` | The Kubernetes API of the cluster, for `kubectl` and other tools | [Kubernetes](kubernetes.md) |

Tunneler must be installed first: a coordinator, and an exit node in the
cluster. See the [self-hosting guide](../self-hosting.md).

## Contents

- [1. How a service is offered](#1-how-a-service-is-offered)
- [2. Labels](#2-labels)
- [3. Roles](#3-roles)
- [4. Readiness](#4-readiness)
- [5. How people connect](#5-how-people-connect)
- [6. The audit trail](#6-the-audit-trail)
- [7. Services from a file](#7-services-from-a-file)

## 1. How a service is offered

The namespace that owns a service registers it. It creates a `TunnelService`
resource next to the service:

```yaml
apiVersion: tunneler.marconet.com/v1alpha1
kind: TunnelService
metadata:
  name: postgres
  namespace: shop
spec:
  kind: postgres          # which kind of service this is
  credentials: ...        # for kinds that have a credential (see the kind)
  grantableRoles: [...]   # what a person can be given here (see section 3)
  labels:                 # how grants and people select it (see section 2)
    team: shop
```

The exit node of the cluster watches these resources in all namespaces. When
you create one, the exit node tells the coordinator about the service. When
you delete it, the service goes away. Nothing changes on the coordinator.

The coordinator knows the service as `<namespace>-<name>`, for example
`shop-postgres`. Thus two namespaces can each have a service with the name
`postgres`.

The resource contains no secret. For a kind that has a credential, the
resource says where the credential is.

## 2. Labels

Labels do two jobs. Grants use them to say who can reach a service. People
use them to say which service they want.

Each service has the labels that its `TunnelService` gives, and four labels
that tunneler sets:

| Label | Value |
|---|---|
| `cluster` | The name of the cluster, from the exit node |
| `kind` | `postgres` or `kubernetes` |
| `name` | The name of the service, for example `shop-postgres` |
| `namespace` | The namespace of the `TunnelService` |

A `TunnelService` cannot set these four labels. Thus a grant for
`cluster: prod` is safe: a service in a different cluster cannot claim it.

For grants, see [section 6 of the self-hosting guide](../self-hosting.md#6-grants-who-can-reach-what).

## 3. Roles

A grant gives a person `roles` on the services that it selects. The meaning
of a role depends on the kind:

| Kind | A role is |
|---|---|
| `postgres` | A database role. The temporary account becomes a member of it |
| `kubernetes` | A group. The cluster sees the person as a member of it |

`grantableRoles` in the `TunnelService` is a limit. It lists the roles that
the exit node gives here, and the exit node refuses all others. This limit is
in the cluster, where the coordinator cannot change it.

CAUTION: Make the `roles` of the grants and the `grantableRoles` of the
services agree. If a grant gives a role that a service does not list, people
with that grant cannot use that service.

## 4. Readiness

The exit node examines each service every 30 seconds. It makes sure that it
can reach the service with its credential. The result is in two places:

```bash
kubectl get tunnelservice --all-namespaces
tunneler services list
```

| `REASON` | Meaning |
|---|---|
| `Connected` | The service is ready |
| `CredentialsInvalid` | The exit node cannot read the credential that the resource refers to |
| `Unreachable` | The exit node has the credential, and the service refuses it or does not answer |
| `InvalidSpec` | The resource is incorrect. The message says why |

The coordinator lists a service that is not ready, and refuses connections to
it with the reason.

## 5. How people connect

One command connects to all kinds of service:

```bash
tunneler services list
tunneler connect cluster=prod team=shop
```

The labels must match exactly one service. If they match more than one, the
command lists them and asks you to select one. `name=<service>` always
matches one service at most. With no labels, the command lists all services
that you can reach.

What the command does then depends on the kind. For `postgres`, it opens a
local port and continues to run. For `kubernetes`, it adds a context to your
kubeconfig and stops. See the document of the kind.

For all kinds, a command after `--` runs with the connection in its
environment, and nothing stays afterwards:

```bash
tunneler connect cluster=prod team=shop -- psql
tunneler connect cluster=prod kind=kubernetes -- kubectl get pods
```

Tunneler records all that a person does through it, with the identity of the
person. `tunneler connect` tells the person so each time.

## 6. The audit trail

The coordinator writes an audit record for all that a person does through
it. Each record is one JSON line in the log of the coordinator, with
`"audit":true`. Records of all kinds of service have these fields:

| Field | Meaning |
|---|---|
| `user` | The person, as the identity provider names them |
| `subject` | The same person, by the permanent ID from the identity provider |
| `cluster` | The cluster of the service |
| `service` | The name of the service |
| `kind` | `postgres` or `kubernetes` |

Thus one search finds all that a person did, or all that occurred on a
service, for all kinds. For example, in a log system that has these fields:

```
audit:true user:alice@example.com cluster:prod
```

Each kind adds its own fields, for example the SQL statement or the
Kubernetes verb. See the document of the kind.

## 7. Services from a file

An exit node can also read services from a file. Use this on a laptop, or
for a cluster without the `TunnelService` resource:

```bash
tunneler start exit --cluster dev --server http://localhost:8443 --config exit.json
```

```json
{
  "services": [
    {
      "name": "orders-db",
      "kind": "postgres",
      "dsn": "postgres://admin:$ORDERS_DB_PASSWORD@localhost:5432/orders?sslmode=disable",
      "labels": {"team": "shop"},
      "roles": ["readonly"]
    }
  ]
}
```

`roles` in the file is the same as `grantableRoles` in the resource. The
exit node reads the file again when it changes. An exit node can use the file
and the resources at the same time.
