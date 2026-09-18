# tunneler

Identity-aware access to services inside Kubernetes clusters. Users sign in
with Entra, get a fully audited temporary sessions to services inside the cluster.
It is designed to be dead-simple, and easy to host. It has three components:

1. **Coordinator.** This is a central server where all clients and exit nodes connect.
2. **Exit nodes.** These are deployed in one or more Kubernetes clusters where you want to expose access to a service.
3. **Client.** This is a CLI installed on your machine that you can use to access a service.

![](/Users/clarkmccauley/Documents/repos/clustertunnel/docs/architecture.png)

## How can I use it?
Tunneler exit nodes connect to a tunneler coordinator using OIDC to authenticate. 
These exit nodes running within Kubernetes clusters look for CRDs like this that allow your application
to "register" a service with the tunneler.

```yaml
apiVersion: tunneler.marconet.com/v1alpha1
kind: TunnelService
metadata:
  name: my-postgres-db
spec:
  kind: postgres
  credentials:
    dsnRef:
      kubernetesSecret:
        name: postgres-secret
        key: database_uri
  grantableRoles:
    - pg_read_all_data
  labels:
    env: stage
```

Clients can connect to the coordinator to get access to this service

```shell
# Configure your client to connect to this coordination server
$ tunneler config --server https://<coordination server>.com

# Log in using the identity provider configured in the coordination server
$ tunneler auth login

# List the available services
$ tunneler services list
CLUSTER   SERVICE          KIND       STATUS   LABELS
dev       my-postgres-db   postgres   ready    cluster=dev,env=stage,kind=postgres,name=my-postgres-db

# Connect to the postgres
$ tunneler connect cluster=dev name=my-postgres-db
22:47:19  Requesting access to the service labelled cluster=dev,name=my-postgres-db...
22:47:19  Access granted to dev/my-postgres-db: temporary account tnl_clark_com_utrt7i7b is provisioned.

  Host:      127.0.0.1
  Port:      55344
  Database:  postgres
  User:      tnl_clark_com_utrt7i7b
  Password:  NHW6GJYSR3DRILQJZL3JJK6S36
  Expires:   2026-09-18 06:47:19

  URL:       postgres://tnl_clark_com_utrt7i7b:NHW6GJYSR3DRILQJZL3JJK6S36@127.0.0.1:55344/postgres?sslmode=disable
  psql:      psql 'postgres://tnl_clark_com_utrt7i7b:NHW6GJYSR3DRILQJZL3JJK6S36@127.0.0.1:55344/postgres?sslmode=disable'

  Everything you run is audited as clark.mccauley@marconet.com.

22:47:19  Listening on 127.0.0.1:55344. Press Ctrl-C to disconnect and revoke the session.
```