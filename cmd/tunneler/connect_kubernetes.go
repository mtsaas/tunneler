package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/mtsaas/tunneler/internal/api"
)

const kubeAuditNotice = "NOTICE: Access to this cluster is audited. Every request you make is logged with your identity."

// connectKubernetes reaches a cluster's API. There is no session to hold
// and no account: every request carries the person's login to the
// coordinator's gateway. So connecting is only a matter of telling kubectl
// where the gateway is and how to get the login, which a kubeconfig context
// does. With a command, the context lives in a file of its own for as long
// as the command runs.
func connectKubernetes(ctx context.Context, c *client, cluster string, svc api.Service, opts connectOptions) error {
	if opts.port != 0 {
		return usageError{errors.New("--port applies to services reached over a local port, and a kubernetes service is not")}
	}
	if !strings.HasPrefix(c.Server, "https://") {
		// kubectl sends no credentials over plain HTTP, so such a context
		// could never log in, and would not say why.
		return fmt.Errorf("kubectl needs the coordinator to be reached over https, and %s is not", c.Server)
	}
	name := opts.context
	if name == "" {
		name = "tunneler-" + cluster
	}
	server := c.GatewayURL(cluster, svc.Name)

	if len(opts.command) > 0 {
		dir, err := os.MkdirTemp("", "tunneler-kubeconfig-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		file := filepath.Join(dir, "config")
		if err := writeKubeContext(file, name, server, c.Server, true); err != nil {
			return err
		}
		if !outputJSON {
			fmt.Fprintf(os.Stderr, "%s\n\n", kubeAuditNotice)
		}
		// Ctrl-C belongs to the command, which shares our terminal.
		child := exec.CommandContext(context.WithoutCancel(ctx), opts.command[0], opts.command[1:]...)
		child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
		child.Env = append(os.Environ(), "KUBECONFIG="+file)
		return child.Run()
	}

	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	file := rules.GetDefaultFilename()
	if err := writeKubeContext("", name, server, c.Server, !opts.noUse); err != nil {
		return err
	}
	text := fmt.Sprintf("Added context %q to %s.\n\n%s\n\n    kubectl --context %s get pods\n", name, file, kubeAuditNotice, printable(name))
	if !opts.noUse {
		text = fmt.Sprintf("Added context %q to %s and made it current.\n\n%s\n\n    kubectl get pods\n", name, file, kubeAuditNotice)
	}
	result(map[string]string{
		"event": "configured", "context": name, "cluster": cluster, "service": svc.Name,
		"server": server, "kubeconfig": file, "notice": kubeAuditNotice,
	}, text)
	return nil
}

// writeKubeContext adds or replaces a cluster, a user and a context of the
// given name. It writes to file, or to the person's kubeconfig if file is
// empty. The context holds no credential: kubectl runs "tunneler kube token"
// for one.
func writeKubeContext(file, name, server, coordinatorURL string, use bool) error {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if file != "" {
		rules = &clientcmd.ClientConfigLoadingRules{ExplicitPath: file}
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			return err
		}
	}
	cfg, err := rules.GetStartingConfig()
	if err != nil {
		return err
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
	return clientcmd.ModifyConfig(rules, *cfg, false)
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
