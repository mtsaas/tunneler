# Kubernetes

This document tells you how to offer the Kubernetes API of a cluster through
tunneler, and how people connect to it. People use `kubectl`, and other tools
that read a kubeconfig, through the coordinator. The coordinator records each
request with the name of the person.

Tunneler must be installed first. See the
[self-hosting guide](../self-hosting.md). For the ideas that all kinds of
service share, see [Services](README.md).

## Contents

- [1. How it works](#1-how-it-works)
- [2. Set up a cluster](#2-set-up-a-cluster)
- [3. Connect](#3-connect)
- [4. The audit trail](#4-the-audit-trail)
- [5. Security](#5-security)
- [6. Problems and their causes](#6-problems-and-their-causes)
- [7. Limits](#7-limits)

## 1. How it works

A request from `kubectl` goes through four parts:

```
kubectl → coordinator → exit node → Kubernetes API server
```

Access to a cluster is different from access to a database.

**There is no temporary account.** For a database, tunneler creates an
account and removes it later. For a cluster, the exit node tells the API
server who the person is, for each request. Kubernetes calls this
impersonation.

**The cluster decides what a person can do.** Tunneler says who the person is
and which groups the person has. The RBAC rules of the cluster give those
groups their permissions. Tunneler has no list of permitted verbs or
resources.

**There is no session.** The coordinator examines the login and the grants
for each request. If you remove a grant, the next request fails.

**The credential stays in the cluster.** The exit node uses its own service
account to speak to the API server. The coordinator does not have this
credential, and the person does not have it.

**The kubeconfig holds no secret.** It contains the address of the
coordinator and the name of a command. `kubectl` runs that command,
`tunneler kube token`, to get the login of the person.

The groups are the link between the three places that you configure:

| Place | What you write there |
|---|---|
| The exit node chart | The groups that people can get in this cluster |
| The RBAC of the cluster | What each group can do |
| The grants of the coordinator | Which people get which groups |

## 2. Set up a cluster

Do this procedure for each cluster. The coordinator and the exit node must
have version 0.3.0 or later. To upgrade them, see
[Upgrades](../self-hosting.md#upgrades).

1. Select names for the groups, for example `tunneler:view` and
   `tunneler:edit`. The names have no special meaning to Kubernetes.

2. Give each group its permissions in the cluster:

   ```bash
   kubectl create clusterrolebinding tunneler-view --clusterrole=view --group=tunneler:view
   ```

   For permissions in one namespace, use a RoleBinding.

3. Enable the feature in the exit node chart, with the same groups:

   ```yaml
   kubernetes:
     enabled: true
     groups: ["tunneler:view"]
     labels: {}
   ```

   The chart then does two things. It registers the cluster with the exit
   node, as a `TunnelService` of kind `kubernetes` with the name
   `kubernetes`. It also lets the exit node impersonate all users, and these
   groups only.

   `groups` must contain at least one group. If it is empty, Helm stops
   with an error that names `kubernetes.groups`. The reason: in a
   ClusterRole, an empty list of names permits all names, `system:masters`
   too.

   NOTE: Helm does not upgrade the custom resource definition of a chart. If
   you installed an earlier version with Helm, apply the definition first:
   `kubectl apply --server-side -f charts/tunneler-exit/crds`. Argo CD does
   this for you.

4. Add a grant to the configuration of the coordinator. For a `kubernetes`
   service, the `roles` of the grant are the groups:

   ```json
   {"group": "<entra-group-id>", "labels": {"cluster": "prod", "kind": "kubernetes"}, "roles": ["tunneler:view"]}
   ```

   The coordinator reads the file again when it changes. A restart is not
   necessary.

5. Make sure that the service is ready:

   ```bash
   kubectl -n tunneler get tunnelservice
   ```

   The `kubernetes` line must show `READY True`.

CAUTION: Make the groups in the chart and the `roles` in the grants agree. If
a grant gives a group that the chart does not list, the exit node refuses all
requests of that person.

## 3. Connect

Each person does this one time for each cluster:

```bash
tunneler connect cluster=prod kind=kubernetes
```

The command adds a context with the name `tunneler-prod` to the kubeconfig,
makes it the current context, and stops. No process continues to run. After
that, `kubectl`, `k9s`, `helm`, and other tools operate as usual:

```bash
kubectl get pods
```

Other options:

- `--context NAME` gives the context a different name.
- `--use=false` keeps the current context as it is.
- To run one command and change nothing, put the command after `--`. The
  command gets a temporary kubeconfig, and tunneler removes it afterwards:

  ```bash
  tunneler connect cluster=prod kind=kubernetes -- kubectl get pods
  ```

When the login expires, `kubectl` gets a new one from tunneler. If tunneler
cannot renew the login, `kubectl` shows an error. The person then runs
`tunneler auth login` again.

To see what access you have, run `tunneler auth status`. To ask the cluster
what it thinks of you, run `kubectl auth whoami`.

## 4. The audit trail

The coordinator writes one record for each request, with the message
`kubernetes request`. The record has the
[fields that all kinds share](README.md#6-the-audit-trail), with
`"kind":"kubernetes"`, and these:

```json
{"msg":"kubernetes request","audit":true,"user":"alice@example.com","subject":"...","cluster":"prod",
 "service":"kubernetes","kind":"kubernetes","verb":"delete","resource":"pods",
 "namespace":"shop","name":"web-0","status":403,"duration":"2ms"}
```

| Field | Meaning |
|---|
| `verb` | `get`, `list`, `watch`, `create`, `update`, `patch`, `delete`, or `deletecollection` |
| `api_group`, `resource`, `subresource`, `namespace`, `name` | What the request was about |
| `status` | The HTTP status that the API server gave. `403` means that RBAC refused the request |
| `command` | For `exec` and `attach`, the command that the person started |
| `aborted` | `true` if the person stopped the request before it was complete, for example with Ctrl-C on `logs -f` |

A request that stays open, such as `exec`, `logs -f`, `port-forward`, or a
watch, gets a second record when it starts. Its message is `kubernetes request started`.

If the coordinator cannot record the start of a request that stays open, it
refuses the request with status 503. See
[the audit trail](README.md#6-the-audit-trail).

The record does not contain the body of a request or of a response. Bodies
can contain secrets.

The audit log of the cluster also names the person. There, the record shows
the person as the user, and the service account of the exit node as the
impersonator.

## 5. Security

- The exit node refuses a group that is not in its list. This limits what a
  coordinator with a fault, or an attacker who controls the coordinator, can
  do in the cluster. Do not put `system:masters` in the list.
- The ClusterRole of the exit node permits it to impersonate only the groups
  in `kubernetes.groups`. This limits what an attacker who gets the service
  account token of the exit node can do. For this reason, the chart refuses
  an empty list.
- The exit node refuses a user whose name starts with `system:`. Those names
  are for nodes, service accounts, and the control plane.
- The coordinator removes `Authorization` and all `Impersonate-` headers that
  a request contains. A person cannot select their own identity.
- A `TunnelService` of kind `kubernetes` operates in the namespace of the
  exit node only. A different namespace cannot offer the API of the cluster.
- A person without access gets the same answer for a cluster that exists and
  for one that does not. The answer does not show which clusters there are.
- The coordinator must have an `https://` address. `kubectl` does not send a
  login to an `http://` address, and `tunneler connect` refuses such a
  coordinator for this kind of service.

## 6. Problems and their causes

| What you see | Cause | What to do |
|---|---|---|
| Helm stops with `kubernetes.groups must list at least one group when kubernetes.enabled` | `kubernetes.enabled` is `true`, but `kubernetes.groups` is empty | Add the groups to `kubernetes.groups`. See [2. Set up a cluster](#2-set-up-a-cluster) |
| `tunneler connect` finds no service | No exit node offers the cluster, or no grant gives you access | Run `tunneler services list` and `tunneler auth status` |
| `Forbidden: tunneler: no such service, or access denied` | No grant selects the service | Add a grant with `kind: kubernetes` for the cluster |
| `Forbidden: tunneler: group "x" is not one this exit node may grant` | A grant gives a group that the chart does not list | Add the group to `kubernetes.groups`, or remove it from the grant |
| `Forbidden: User "alice@..." cannot list resource ...` | The login is correct, but RBAC does not permit the action | Bind the group to a role that permits it |
| `You must be logged in to the server` | The login expired and tunneler could not renew it | Run `tunneler auth login` |
| `the cluster's exit node could not be reached` | The exit node is not connected | Examine the pods of the exit node and their logs |
| The `TunnelService` shows `READY False` | The exit node cannot reach the API server with its service account | Read the `REASON` column and the log of the exit node |
| `kubectl get` operates, but `k9s` shows empty lists and no error | Something between the person and the coordinator holds data of an open HTTP/2 response. New versions of `k9s` and other tools get their lists from such a response | Start the tool with `DISABLE_HTTP2=1` to make sure that this is the cause. Then make the ingress give HTTP/1.1 for the coordinator, or let the coordinator terminate TLS itself. `go run ./hack/informerprobe CONTEXT` measures this |
| `kubectl exec` stops immediately behind an ingress | The ingress does not pass the connection upgrade | Use `kubectl` 1.31 or later, which uses WebSocket |

## 7. Limits

- The coordinator records that a person started `exec`, and the command. It
  does not record what the person types in the shell, or what the shell
  shows.
- If the coordinator is down, `kubectl` through it does not work. Keep a
  second way into each cluster for a small group of administrators, for
  example `az aks get-credentials`.
- One coordinator serves all requests. It is not a load balancer for the API
  server. Large transfers, such as `kubectl cp` of big files, go through it.
