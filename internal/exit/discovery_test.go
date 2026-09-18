package exit

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func tunnelService(ns, name string, spec map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "tunneler.marconet.com/v1alpha1",
		"kind":       "TunnelService",
		"metadata":   map[string]any{"name": name, "namespace": ns, "generation": int64(1)},
		"spec":       spec,
	}}
}

func TestDiscovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// An unreachable but well-formed DSN, and a reference to a missing Secret.
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "orders-secrets", Namespace: "preview-1"},
		Data:       map[string][]byte{"database_uri": []byte("postgres://admin:pw@127.0.0.1:1/orders?sslmode=disable")},
	}
	ownSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "tunneler"},
		Data:       map[string][]byte{"dsn": []byte("postgres://admin:pw@127.0.0.1:1/shared?sslmode=disable")},
	}
	good := tunnelService("preview-1", "postgres", map[string]any{
		"kind":           "postgres",
		"credentials":    map[string]any{"dsnRef": map[string]any{"kubernetesSecret": map[string]any{"name": "orders-secrets", "key": "database_uri"}}},
		"grantableRoles": []any{"readonly"},
		"labels":         map[string]any{"environment": "preview-1"},
	})
	broken := tunnelService("preview-2", "postgres", map[string]any{
		"kind":        "postgres",
		"credentials": map[string]any{"dsnRef": map[string]any{"kubernetesSecret": map[string]any{"name": "nope", "key": "database_uri"}}},
	})

	scheme := runtime.NewScheme()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{TunnelServiceGVR: "TunnelServiceList"}, good)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent := &Agent{Log: log}
	d := &Discovery{Agent: agent, Namespace: "tunneler", Dynamic: dyn, Clients: k8sfake.NewSimpleClientset(secret, ownSecret), Log: log}
	go d.Run(ctx)

	// The pre-existing resource is discovered and named <namespace>-<name>.
	waitFor(t, ctx, func() bool { _, ok := agent.desired()["preview-1-postgres"]; return ok })
	svc := agent.desired()["preview-1-postgres"]
	if svc.advert.Labels["environment"] != "preview-1" || svc.advert.Labels["namespace"] != "preview-1" || svc.roles[0] != "readonly" {
		t.Errorf("service = %+v", svc.advert)
	}

	// It cannot be reached, so it is advertised as not ready, and both the
	// advertisement and its status say why.
	agent.reconcile(ctx)
	adverts := *agent.adverts.Load()
	if len(adverts) != 1 || adverts[0].Ready || adverts[0].Status == "" {
		t.Errorf("adverts = %+v", adverts)
	}
	if got := condition(t, ctx, dyn, "preview-1", "postgres"); got.Status != metav1.ConditionFalse || got.Reason != "Unreachable" {
		t.Errorf("status after failed ping = %+v", got)
	}

	// A resource with a missing Secret defines nothing and says so.
	if _, err := dyn.Resource(TunnelServiceGVR).Namespace("preview-2").Create(ctx, broken, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ctx, func() bool {
		c := condition(t, ctx, dyn, "preview-2", "postgres")
		return c != nil && c.Reason == "CredentialsInvalid"
	})
	if _, ok := agent.desired()["preview-2-postgres"]; ok {
		t.Error("service with unresolvable credentials was defined")
	}

	create := func(ns, name string, spec map[string]any) {
		t.Helper()
		if _, err := dyn.Resource(TunnelServiceGVR).Namespace(ns).Create(ctx, tunnelService(ns, name, spec), metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	invalid := func(ns, name, why string) {
		t.Helper()
		waitFor(t, ctx, func() bool {
			c := condition(t, ctx, dyn, ns, name)
			return c != nil && c.Reason == "InvalidSpec" && strings.Contains(c.Message, why)
		})
	}
	ownDB := map[string]any{
		"kind":        "postgres",
		"credentials": map[string]any{"dsnRef": map[string]any{"kubernetesSecret": map[string]any{"name": "db", "key": "dsn"}}},
	}

	// In the exit node's own namespace a service keeps its plain name.
	create("tunneler", "shared-db", ownDB)
	waitFor(t, ctx, func() bool { _, ok := agent.desired()["shared-db"]; return ok })
	if got := agent.desired()["shared-db"].advert.Labels["namespace"]; got != "tunneler" {
		t.Errorf("namespace label = %q", got)
	}

	// Which makes a clash possible, and the later resource loses.
	create("tunneler", "preview-1-postgres", ownDB)
	invalid("tunneler", "preview-1-postgres", "already taken by the TunnelService preview-1/postgres")

	// A tenant cannot offer the cluster's own API.
	create("preview-2", "kubernetes", map[string]any{"kind": "kubernetes", "grantableRoles": []any{"system:masters"}})
	invalid("preview-2", "kubernetes", "only be registered in the exit node's namespace")
	if _, ok := agent.desired()["preview-2-kubernetes"]; ok {
		t.Error("a tenant's kubernetes service was defined")
	}

	// Deleting the resource withdraws its service.
	if err := dyn.Resource(TunnelServiceGVR).Namespace("preview-1").Delete(ctx, "postgres", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ctx, func() bool { _, ok := agent.desired()["preview-1-postgres"]; return !ok })
}

func waitFor(t *testing.T, ctx context.Context, cond func() bool) {
	t.Helper()
	for !cond() {
		if ctx.Err() != nil {
			t.Fatal("condition never met")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func condition(t *testing.T, ctx context.Context, dyn *dynamicfake.FakeDynamicClient, ns, name string) *metav1.Condition {
	t.Helper()
	u, err := dyn.Resource(TunnelServiceGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ts, err := toTunnelService(u)
	if err != nil {
		t.Fatal(err)
	}
	for i := range ts.Status.Conditions {
		if ts.Status.Conditions[i].Type == "Ready" {
			return &ts.Status.Conditions[i]
		}
	}
	return nil
}
