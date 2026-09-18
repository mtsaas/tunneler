package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/mtsaas/tunneler/internal/exit"
	"github.com/mtsaas/tunneler/internal/version"
)

func startExitCmd() *cobra.Command {
	var path, healthAddr, tokenFile string
	var kubernetes bool
	a := &exit.Agent{}
	cmd := &cobra.Command{
		Use:   "exit",
		Short: "Run the exit node for a cluster",
		Long: `Run the exit node for a cluster.

Everything but the cluster name has a default suited to a Kubernetes
Deployment. The coordinator URL comes from $TUNNELER_SERVER and the cluster
name from $TUNNELER_CLUSTER. The node proves which cluster it speaks for with,
in order of preference: a projected service account token at --token-file,
which the coordinator verifies against the cluster's own OIDC issuer; Azure
Workload Identity, whose managed identity needs the app role "exit:<cluster>";
or nothing, which only a coordinator running with insecure_exit_auth, for
local development, accepts.

Services come from the configuration file, from TunnelService resources in
the cluster with --kubernetes (see deploy/crd.yaml), or both. A service is
advertised only once its credentials have connected. /healthz answers 200 while the process runs
and /readyz while it is connected to the coordinator. Services are defined in the configuration file:

  {
    "services": [
      {
        "name": "orders-db",
        "kind": "postgres",
        "dsn": "postgres://tunneler:$ORDERS_DB_PASSWORD@orders-db.shop.svc:5432/orders?sslmode=require",
        "labels": {"team": "shop", "tier": "primary"},
        "roles": ["readonly", "readwrite"]
      }
    ]
  }

Users select services by label. Each also carries the labels cluster, kind
and name automatically. The kind tells the coordinator which protocol-aware proxy to put in front of
the service.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a.Log = log
			log.Info("tunneler exit node starting", "version", version.String())
			a.Server = strings.TrimRight(cmp.Or(a.Server, os.Getenv("TUNNELER_SERVER")), "/")
			if a.Server == "" {
				return errors.New("--server or $TUNNELER_SERVER is required")
			}
			azure, azureErr := exit.NewAzureCredential()
			if _, err := os.Stat(tokenFile); err == nil {
				log.Info("authenticating to the coordinator with this cluster's service account token; the coordinator must trust the cluster's issuer",
					"file", tokenFile)
				a.Token = exit.TokenFile(tokenFile)
			} else if azure != nil {
				log.Info("authenticating to the coordinator with Azure Workload Identity",
					"client_id", os.Getenv("AZURE_CLIENT_ID"), "needs_role", "exit:"+a.Cluster)
				a.Token = exit.AzureWorkloadIdentity(azure, a.Server)
			} else {
				log.Warn("connecting to the coordinator WITHOUT credentials; it will refuse unless it runs with insecure_exit_auth",
					"no_token_file", tokenFile, "no_workload_identity", azureErr)
			}
			a.Cluster = cmp.Or(a.Cluster, os.Getenv("TUNNELER_CLUSTER"))
			if a.Cluster == "" {
				return errors.New("--cluster or $TUNNELER_CLUSTER is required")
			}
			ctx := cmd.Context()
			if _, err := os.Stat(path); err == nil {
				if err := a.LoadConfig(path); err != nil {
					return err
				}
				go a.WatchConfig(ctx, path)
			} else if !kubernetes {
				return fmt.Errorf("no services: %s does not exist and --kubernetes is off", path)
			}
			if kubernetes {
				d, err := newDiscovery(a, azure)
				if err != nil {
					return err
				}
				go func() {
					if err := d.Run(ctx); !errors.Is(err, context.Canceled) {
						log.Error("TunnelService discovery stopped", "err", err)
					}
				}()
			}
			go serveHealth(ctx, healthAddr, a)
			if err := a.Run(ctx); !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&a.Cluster, "cluster", "", "name of this cluster (default $TUNNELER_CLUSTER)")
	cmd.Flags().StringVar(&healthAddr, "health-addr", ":8081", "address of the /healthz and /readyz endpoints; empty disables them")
	cmd.Flags().StringVar(&a.Server, "server", "", "coordinator URL (default $TUNNELER_SERVER)")
	cmd.Flags().StringVar(&tokenFile, "token-file", "/var/run/secrets/tunneler/token", "projected service account token to authenticate with, if present")
	cmd.Flags().StringVar(&path, "config", "/etc/tunneler/exit.json", "configuration file, if present")
	cmd.Flags().BoolVar(&kubernetes, "kubernetes", false, "also discover services from TunnelService resources in the cluster")
	return cmd
}

// serveHealth answers Kubernetes probes until ctx is done.
func serveHealth(ctx context.Context, addr string, a *exit.Agent) {
	if addr == "" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !a.Healthy() {
			http.Error(w, "not connected to the coordinator", http.StatusServiceUnavailable)
		}
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	context.AfterFunc(ctx, func() { srv.Close() })
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Error("health endpoints unavailable", "addr", addr, "err", err)
	}
}

// newDiscovery connects to the cluster the process runs in, or, outside a
// cluster, to the one the kubeconfig names.
func newDiscovery(a *exit.Agent, azure *exit.AzureCredential) (*exit.Discovery, error) {
	cfg, err := rest.InClusterConfig()
	if errors.Is(err, rest.ErrNotInCluster) {
		cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), nil).ClientConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("kubernetes: %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	clients, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	log.Info("discovering services from TunnelService resources", "api_server", cfg.Host)
	return &exit.Discovery{Agent: a, Dynamic: dyn, Clients: clients, Azure: azure, Log: log}, nil
}
