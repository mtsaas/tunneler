package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/mtsaas/tunneler/internal/coordinator"
)

func startCoordinatorCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "coordinator",
		Short: "Run the central coordinator",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return startCoordinator(cmd.Context(), path) },
	}
	cmd.Flags().StringVar(&path, "config", "/etc/tunneler/config.json", "configuration file")
	return cmd
}

func startCoordinator(ctx context.Context, path string) error {
	cfg, err := coordinator.LoadConfig(path)
	if err != nil {
		return err
	}
	log.Info("configuration loaded", "file", path, "grants", len(cfg.Grants), "admin_groups", len(cfg.Admins),
		"session_ttl", time.Duration(cfg.SessionTTL).String())
	for _, g := range cfg.Grants {
		log.Info("grant: members of group may reach services with these labels", "group", g.Group, "labels", g.Labels, "roles", g.Roles)
	}

	if cfg.InsecureExitAuth {
		log.Warn("insecure_exit_auth is on: ANY exit node is admitted as ANY cluster without credentials. Never run this outside local development.")
	}
	log.Info("discovering identity provider", "issuer", cfg.OIDC.Issuer, "client_id", cfg.OIDC.ClientID)
	auth, err := coordinator.NewOIDCAuthenticator(ctx, cfg.OIDC)
	if err != nil {
		return fmt.Errorf("oidc discovery: %w", err)
	}
	// ponytail: the audit trail shares the process log, marked audit=true.
	// To store it elsewhere, pass a logger with another slog.Handler.
	c, err := coordinator.New(cfg, auth, log, log.With("audit", true))
	if err != nil {
		return err
	}
	defer c.Close()
	srv := coordinator.NewHTTPServer(cfg.Listen, c.Handler())

	errc := make(chan error, 1)
	go func() {
		log.Info("coordinator listening; no clusters are routable until their exit nodes connect",
			"addr", cfg.Listen, "tls", cfg.TLS != nil)
		if cfg.TLS != nil {
			errc <- srv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	log.Info("shutting down; sessions are kept and resume on next start")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
