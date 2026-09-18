package main

import (
	"encoding/json"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// execCredential is the answer of a Kubernetes client-go credential plugin.
type execCredential struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Status     struct {
		Token               string    `json:"token"`
		ExpirationTimestamp time.Time `json:"expirationTimestamp"`
	} `json:"status"`
}

func kubeTokenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "token",
		Short: "Print your login as a kubectl credential",
		Long: `Print your login as a kubectl credential.

kubectl runs this itself, from the context that "tunneler kube config"
writes. It prints an ExecCredential holding your ID token, renewing the token
first if it can. kubectl asks again when the token expires.

Exits with 3 if you are not logged in.`,
		Args: usage(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := authed(cmd.Context())
			if err != nil {
				return err
			}
			token, err := c.token(cmd.Context())
			if err != nil {
				return err
			}
			cred := execCredential{APIVersion: "client.authentication.k8s.io/v1", Kind: "ExecCredential"}
			cred.Status.Token = token
			cred.Status.ExpirationTimestamp = jwtExpiry(token)
			return json.NewEncoder(os.Stdout).Encode(cred)
		},
	}
}
