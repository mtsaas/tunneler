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
	var keyVaultSecrets []string
	a := &exit.Agent{}
	cmd := &cobra.Command{
		Use:   "exit",
		Short: "Run the exit node for a cluster",
		Long: `Run the exit node for a cluster.

Connects out to the coordinator, offers it the cluster's services, and
creates and removes accounts on them.

Services come from TunnelService resources (--kubernetes), from the
configuration file, or both. A service is offered once its credentials work.
A TunnelService may use only the Key Vault secrets that --key-vault-secret
lists for its namespace.

Proves which cluster it is with, in order: the service account token at
--token-file; Azure Workload Identity; or nothing, which only a coordinator
with insecure_exit_auth accepts.

Serves /healthz, and /readyz while connected to the coordinator.`,
		Example: `$ tunneler start exit --kubernetes
$ tunneler start exit --cluster dev --server http://localhost:8443 --config exit.json`,
		Args: usage(cobra.NoArgs),
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
				allowed, err := exit.ParseKeyVaultSecrets(keyVaultSecrets)
				if err != nil {
					return usageError{fmt.Errorf("--key-vault-secret: %w", err)}
				}
				d, err := newDiscovery(a, azure)
				if err != nil {
					return err
				}
				d.KeyVaultSecrets = allowed
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
	cmd.Flags().StringVar(&a.Cluster, "cluster", "", "Name of this cluster (default $TUNNELER_CLUSTER)")
	cmd.Flags().StringVar(&healthAddr, "health-addr", ":8081", "Address for /healthz and /readyz; empty to disable")
	cmd.Flags().StringVar(&a.Server, "server", "", "URL of the coordinator (default $TUNNELER_SERVER)")
	cmd.Flags().StringVar(&tokenFile, "token-file", "/var/run/secrets/tunneler/token", "Service account token to authenticate with, if present")
	cmd.Flags().StringVar(&path, "config", "/etc/tunneler/exit.json", "Configuration file, if present")
	cmd.Flags().BoolVar(&kubernetes, "kubernetes", false, "Discover services from TunnelService resources")
	cmd.Flags().StringArrayVar(&keyVaultSecrets, "key-vault-secret", nil,
		"Let TunnelService resources in NAMESPACE use a Key Vault secret, as NAMESPACE=https://VAULT.vault.azure.net/secrets/NAME; repeat for more")
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
	// Outside a pod there is no such file, and no namespace is ours.
	namespace, _ := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	log.Info("discovering services from TunnelService resources", "api_server", cfg.Host, "own_namespace", strings.TrimSpace(string(namespace)))
	return &exit.Discovery{Agent: a, Namespace: strings.TrimSpace(string(namespace)), Dynamic: dyn, Clients: clients, Azure: azure, Log: log}, nil
}
