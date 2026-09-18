package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/coordinator"
)

func kubeConfigCmd() *cobra.Command {
	var context string
	var use bool
	cmd := &cobra.Command{
		Use:   "config [LABEL=VALUE...]",
		Short: "Add a cluster to your kubeconfig",
		Long: `Add a cluster to your kubeconfig.

Writes a context that reaches the cluster's API through the coordinator, as
you. kubectl and every other tool that reads a kubeconfig then work as usual,
with no tunnel to keep open. The context holds no credential: kubectl gets
your login from "tunneler kube token" when it needs it.

What you may do is decided by the cluster's own RBAC, for the groups your
grants give you. Every request is logged with your identity.`,
		Annotations: map[string]string{
			helpArguments: selectorArguments + `

Only services of kind kubernetes are considered.`,
			helpJSON: `{"context", "cluster", "service", "server", "kubeconfig"}`,
		},
		Example: `$ tunneler kube config cluster=prod
$ tunneler kube config cluster=prod --context prod --use=false
$ kubectl --context tunneler-prod get pods`,
		RunE: func(cmd *cobra.Command, args []string) error {
			selector, err := parseSelector(args)
			if err != nil {
				return err
			}
			selector["kind"] = "kubernetes"
			c, err := authed(cmd.Context())
			if err != nil {
				return err
			}
			if !strings.HasPrefix(c.Server, "https://") {
				// kubectl sends no credentials over plain HTTP, so such a context
				// could never log in, and would not say why.
				return fmt.Errorf("kubectl needs the coordinator to be reached over https, and %s is not", c.Server)
			}
			clusters, err := c.Services(cmd.Context())
			if err != nil {
				return err
			}
			cluster, svc, err := selectOne(clusters, selector)
			if err != nil {
				return err
			}
			if context == "" {
				context = "tunneler-" + cluster
			}
			path, err := writeKubeContext(context, c.GatewayURL(cluster, svc.Name), c.Server, use)
			if err != nil {
				return err
			}
			text := fmt.Sprintf("Added context %q to %s.\n\n%s\n\n    kubectl --context %s get pods\n",
				context, path, kubeAuditNotice, context)
			if use {
				text = fmt.Sprintf("Added context %q to %s and made it current.\n\n%s\n\n    kubectl get pods\n",
					context, path, kubeAuditNotice)
			}
			result(map[string]string{
				"context": context, "cluster": cluster, "service": svc.Name,
				"server": c.GatewayURL(cluster, svc.Name), "kubeconfig": path, "notice": kubeAuditNotice,
			}, text)
			return nil
		},
	}
	cmd.Flags().StringVar(&context, "context", "", "Name of the context (default: tunneler-CLUSTER)")
	cmd.Flags().BoolVar(&use, "use", true, "Make the context current")
	return cmd
}

const kubeAuditNotice = "NOTICE: Access through this context is audited. Every request you make is logged with your identity."

// selectOne returns the one service the selector matches. If it matches
// several, the error lists them, as the coordinator's does for connect.
func selectOne(clusters []api.Cluster, selector map[string]string) (cluster string, svc api.Service, err error) {
	grant := coordinator.Grant{Labels: selector}
	var matches []api.Cluster
	n := 0
	for _, cl := range clusters {
		var services []api.Service
		for _, s := range cl.Services {
			if grant.Matches(s.Labels) {
				services = append(services, s)
			}
		}
		if len(services) > 0 {
			matches = append(matches, api.Cluster{Name: cl.Name, Services: services})
			n += len(services)
		}
	}
	switch n {
	case 0:
		return "", api.Service{}, &api.Error{Status: 403, Message: "no service you have access to matches " + formatLabels(selector)}
	case 1:
		return matches[0].Name, matches[0].Services[0], nil
	}
	if !outputJSON {
		fmt.Fprintf(os.Stderr, "More than one service matches:\n\n")
		printServices(os.Stderr, matches, false)
		fmt.Fprintln(os.Stderr)
	}
	return "", api.Service{}, &api.Error{
		Status:  409,
		Message: fmt.Sprintf("the selector matches %d services; add labels until it matches one (name=... always will)", n),
		Matches: matches,
	}
}

// writeKubeContext adds or replaces a cluster, a user and a context of the
// given name in the user's kubeconfig, and returns the file it wrote.
func writeKubeContext(name, server, coordinatorURL string, use bool) (string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	cfg, err := rules.GetStartingConfig()
	if err != nil {
		return "", err
	}
	cfg.Clusters[name] = &clientcmdapi.Cluster{Server: server}
	cfg.AuthInfos[name] = &clientcmdapi.AuthInfo{Exec: &clientcmdapi.ExecConfig{
		APIVersion: "client.authentication.k8s.io/v1",
		Command:    self(),
		Args:       []string{"kube", "token"},
		// The login belongs to a coordinator; name it, in case the
		// configured one changes later.
		Env:             []clientcmdapi.ExecEnvVar{{Name: "TUNNELER_SERVER", Value: coordinatorURL}},
		InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
		InstallHint:     "tunneler is not installed; see https://github.com/mtsaas/tunneler#installation",
	}}
	cfg.Contexts[name] = &clientcmdapi.Context{Cluster: name, AuthInfo: name}
	if use {
		cfg.CurrentContext = name
	}
	if err := clientcmd.ModifyConfig(rules, *cfg, false); err != nil {
		return "", err
	}
	return rules.GetDefaultFilename(), nil
}

// self returns how kubectl should run this program: by name if that finds
// this very binary, so that the kubeconfig survives an upgrade that moves
// it, and by path otherwise.
func self() string {
	exe, err := os.Executable()
	if err != nil {
		return "tunneler"
	}
	if found, err := exec.LookPath(filepath.Base(exe)); err == nil {
		a, errA := filepath.EvalSymlinks(found)
		b, errB := filepath.EvalSymlinks(exe)
		if errA == nil && errB == nil && a == b {
			return filepath.Base(exe)
		}
	}
	return exe
}
