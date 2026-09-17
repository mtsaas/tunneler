package main

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mtsaas/tunneler/internal/exit"
)

func startExitCmd() *cobra.Command {
	var path, healthAddr string
	a := &exit.Agent{}
	cmd := &cobra.Command{
		Use:   "exit",
		Short: "Run the exit node for a cluster",
		Long: `Run the exit node for a cluster.

Everything but the cluster name has a default suited to a Kubernetes
Deployment. The coordinator URL comes from $TUNNELER_SERVER. The node proves
which cluster it speaks for with Azure Workload Identity: its managed identity
needs the app role "exit:<cluster>". Outside such a pod it sends no
credentials, which only a coordinator running with insecure_exit_auth, for
local development, accepts. /healthz answers 200 while the process runs
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
			a.Server = strings.TrimRight(cmp.Or(a.Server, os.Getenv("TUNNELER_SERVER")), "/")
			if a.Server == "" {
				return errors.New("--server or $TUNNELER_SERVER is required")
			}
			if token, err := exit.AzureWorkloadIdentity(a.Server); err != nil {
				log.Warn("connecting to the coordinator WITHOUT credentials; it will refuse unless it runs with insecure_exit_auth", "reason", err)
			} else {
				log.Info("authenticating to the coordinator with Azure Workload Identity",
					"client_id", os.Getenv("AZURE_CLIENT_ID"), "needs_role", "exit:"+a.Cluster)
				a.Token = token
			}
			a.Cluster = cmp.Or(a.Cluster, os.Getenv("TUNNELER_CLUSTER"))
			if a.Cluster == "" {
				return errors.New("--cluster or $TUNNELER_CLUSTER is required")
			}
			if err := a.LoadConfig(path); err != nil {
				return err
			}
			ctx := cmd.Context()
			a.CheckServices(ctx)
			go a.WatchConfig(ctx, path)
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
	cmd.Flags().StringVar(&path, "config", "/etc/tunneler/exit.json", "configuration file")
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
