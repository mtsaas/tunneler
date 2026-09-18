package exit

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// TunnelServiceGVR identifies the TunnelService custom resource. Its
// definition is in deploy/crd.yaml.
var TunnelServiceGVR = schema.GroupVersionResource{Group: "tunneler.marconet.com", Version: "v1alpha1", Resource: "tunnelservices"}

// TunnelService registers a service with the cluster's exit node. It is
// namespaced, so each environment owns its own registrations, and it holds
// only references to credentials, never the credentials themselves.
type TunnelService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              TunnelServiceSpec   `json:"spec"`
	Status            TunnelServiceStatus `json:"status,omitempty"`
}

type TunnelServiceSpec struct {
	Kind        string      `json:"kind"`
	Credentials Credentials `json:"credentials"`
	// GrantableRoles are the roles the coordinator may grant to accounts it
	// provisions here.
	GrantableRoles []string `json:"grantableRoles"`
	// Labels select the service in grants and on the command line, besides
	// the automatic cluster, kind, name and namespace.
	Labels map[string]string `json:"labels,omitempty"`
}

// Credentials say where the administrative DSN is kept.
type Credentials struct {
	DSNRef DSNRef `json:"dsnRef"`
}

// DSNRef points at a complete administrative connection string; exactly one
// field is set.
type DSNRef struct {
	KubernetesSecret *SecretKeyRef `json:"kubernetesSecret,omitempty"`
	AzureKeyVault    *KeyVaultRef  `json:"azureKeyVault,omitempty"`
}

// SecretKeyRef names a key of a Secret in the TunnelService's namespace.
type SecretKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// KeyVaultRef names a secret in an Azure Key Vault that the exit node's
// workload identity can read.
type KeyVaultRef struct {
	VaultURI   string `json:"vaultUri"`
	SecretName string `json:"secretName"`
}

type TunnelServiceStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// Discovery defines the exit node's "kubernetes" services from the
// TunnelService resources of the cluster, keeping them current as resources
// come and go and as their credentials rotate.
type Discovery struct {
	Agent   *Agent
	Dynamic dynamic.Interface
	Clients kubernetes.Interface
	Azure   *AzureCredential // nil outside a workload identity pod; Key Vault references then fail
	// Resync is how often every resource is re-examined regardless of
	// events, which is what picks up a rotated Secret. Default 5m.
	//
	// ponytail: Secrets are re-read on resync rather than watched, which
	// would need cluster-wide list/watch on Secrets.
	Resync time.Duration
	Log    *slog.Logger

	mu       sync.Mutex
	services map[string]*service // by namespace/name
	sources  map[string]string   // by namespace/name: the DSN and generation the service was built from
	statuses map[string]string   // by namespace/name: the last condition written, to avoid rewriting it
}

// Run watches TunnelService resources until ctx is done.
func (d *Discovery) Run(ctx context.Context) error {
	d.services = make(map[string]*service)
	d.sources = make(map[string]string)
	d.statuses = make(map[string]string)
	d.Agent.SetServices("kubernetes", nil)

	factory := dynamicinformer.NewDynamicSharedInformerFactory(d.Dynamic, cmp.Or(d.Resync, 5*time.Minute))
	informer := factory.ForResource(TunnelServiceGVR).Informer()
	_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { d.upsert(ctx, obj) },
		UpdateFunc: func(_, obj any) { d.upsert(ctx, obj) },
		DeleteFunc: func(obj any) { d.remove(obj) },
	})
	if err != nil {
		return err
	}
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return errors.New("kubernetes: watching TunnelService resources: cache never synced")
	}
	d.Log.Info("watching TunnelService resources across all namespaces", "resources", len(d.services))
	<-ctx.Done()
	return ctx.Err()
}

func toTunnelService(obj any) (*TunnelService, error) {
	if tomb, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tomb.Obj
	}
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return nil, fmt.Errorf("unexpected object %T", obj)
	}
	var ts TunnelService
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &ts); err != nil {
		return nil, err
	}
	return &ts, nil
}

// upsert defines or redefines the service for a resource. A resource whose
// credentials cannot be resolved defines nothing and says so in its status.
func (d *Discovery) upsert(ctx context.Context, obj any) {
	ts, err := toTunnelService(obj)
	if err != nil {
		d.Log.Error("ignoring TunnelService event", "err", err)
		return
	}
	key := ts.Namespace + "/" + ts.Name
	log := d.Log.With("tunnelservice", key)

	dsn, err := d.resolveDSN(ctx, ts)
	if err != nil {
		log.Warn("TunnelService credentials cannot be resolved; not offering it", "err", err)
		d.drop(key)
		d.setStatus(ctx, ts, false, "CredentialsInvalid", err.Error())
		return
	}
	// Built from the same spec and the same DSN as before: nothing to do.
	// This is what makes status writes and resyncs cheap.
	source := fmt.Sprintf("%d\x00%s", ts.Generation, dsn)
	d.mu.Lock()
	unchanged := d.sources[key] == source
	d.mu.Unlock()
	if unchanged {
		return
	}

	labels := maps.Clone(ts.Spec.Labels)
	if labels == nil {
		labels = make(map[string]string)
	}
	if _, ok := labels["namespace"]; ok {
		d.drop(key)
		d.setStatus(ctx, ts, false, "InvalidSpec", `label "namespace" is attached automatically and cannot be set`)
		return
	}
	labels["namespace"] = ts.Namespace
	svc, err := newService(ServiceConfig{
		Name:   ts.Namespace + "-" + ts.Name,
		Kind:   ts.Spec.Kind,
		DSN:    dsn,
		Labels: labels,
		Roles:  ts.Spec.GrantableRoles,
	})
	if err != nil {
		log.Warn("TunnelService is invalid; not offering it", "err", err)
		d.drop(key)
		d.setStatus(ctx, ts, false, "InvalidSpec", err.Error())
		return
	}
	svc.report = func(ctx context.Context, ready bool, reason, message string) {
		d.setStatus(ctx, ts, ready, reason, message)
	}
	log.Info("TunnelService defines a service; checking that it is reachable", "service", svc.advert.Name,
		"kind", ts.Spec.Kind, "addr", svc.backend.Addr(), "labels", labels, "grantable_roles", ts.Spec.GrantableRoles)

	d.mu.Lock()
	d.services[key] = svc
	d.sources[key] = source
	d.mu.Unlock()
	d.push()
}

func (d *Discovery) remove(obj any) {
	ts, err := toTunnelService(obj)
	if err != nil {
		d.Log.Error("ignoring TunnelService deletion", "err", err)
		return
	}
	key := ts.Namespace + "/" + ts.Name
	d.Log.Info("TunnelService deleted; withdrawing its service", "tunnelservice", key)
	d.drop(key)
	d.mu.Lock()
	delete(d.statuses, key)
	d.mu.Unlock()
}

// drop forgets the service for a resource, if any, and tells the agent.
func (d *Discovery) drop(key string) {
	d.mu.Lock()
	_, had := d.services[key]
	delete(d.services, key)
	delete(d.sources, key)
	d.mu.Unlock()
	if had {
		d.push()
	}
}

// push hands the agent the current set, keyed by service name.
func (d *Discovery) push() {
	d.mu.Lock()
	services := make(map[string]*service, len(d.services))
	for _, svc := range d.services {
		services[svc.advert.Name] = svc
	}
	d.mu.Unlock()
	d.Agent.SetServices("kubernetes", services)
}

// resolveDSN fetches the administrative DSN the resource refers to.
func (d *Discovery) resolveDSN(ctx context.Context, ts *TunnelService) (string, error) {
	ref := ts.Spec.Credentials.DSNRef
	switch {
	case ref.KubernetesSecret != nil && ref.AzureKeyVault != nil:
		return "", errors.New("dsnRef names both a kubernetesSecret and an azureKeyVault; choose one")
	case ref.KubernetesSecret != nil:
		r := ref.KubernetesSecret
		secret, err := d.Clients.CoreV1().Secrets(ts.Namespace).Get(ctx, r.Name, metav1.GetOptions{})
		if err != nil {
			return "", fmt.Errorf("secret %s/%s: %w", ts.Namespace, r.Name, err)
		}
		dsn, ok := secret.Data[r.Key]
		if !ok || len(dsn) == 0 {
			return "", fmt.Errorf("secret %s/%s has no key %q", ts.Namespace, r.Name, r.Key)
		}
		return string(dsn), nil
	case ref.AzureKeyVault != nil:
		r := ref.AzureKeyVault
		dsn, err := keyVaultSecret(ctx, d.Azure, r.VaultURI, r.SecretName)
		if err != nil {
			return "", fmt.Errorf("key vault %s secret %s: %w", r.VaultURI, r.SecretName, err)
		}
		return dsn, nil
	}
	return "", errors.New("dsnRef names neither a kubernetesSecret nor an azureKeyVault")
}

// setStatus writes the resource's Ready condition, unless it already says
// the same.
func (d *Discovery) setStatus(ctx context.Context, ts *TunnelService, ready bool, reason, message string) {
	key := ts.Namespace + "/" + ts.Name
	status := metav1.ConditionFalse
	if ready {
		status = metav1.ConditionTrue
	}
	summary := fmt.Sprintf("%d %s %s %s", ts.Generation, status, reason, message)
	d.mu.Lock()
	same := d.statuses[key] == summary
	d.statuses[key] = summary
	d.mu.Unlock()
	if same {
		return
	}

	patch, _ := json.Marshal(map[string]any{"status": TunnelServiceStatus{
		ObservedGeneration: ts.Generation,
		Conditions: []metav1.Condition{{
			Type:               "Ready",
			Status:             status,
			Reason:             reason,
			Message:            message,
			ObservedGeneration: ts.Generation,
			LastTransitionTime: metav1.Now(),
		}},
	}})
	_, err := d.Dynamic.Resource(TunnelServiceGVR).Namespace(ts.Namespace).
		Patch(ctx, ts.Name, types.MergePatchType, patch, metav1.PatchOptions{}, "status")
	if err != nil {
		d.Log.Warn("could not write TunnelService status", "tunnelservice", key, "err", err)
		d.mu.Lock()
		delete(d.statuses, key) // try again next time
		d.mu.Unlock()
	}
}
