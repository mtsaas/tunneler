package exit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
	// A DSN that leaves its password to the exit node's environment, which
	// holds the operator's.
	t.Setenv("PGPASSWORD", "operator-secret")
	passwordless := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "preview-3"},
		Data:       map[string][]byte{"dsn": []byte("postgres://admin@127.0.0.1:1/orders?sslmode=disable")},
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
	d := &Discovery{Agent: agent, Namespace: "tunneler", Dynamic: dyn, Clients: k8sfake.NewSimpleClientset(secret, ownSecret, passwordless), Log: log}
	go d.Run(ctx)

	// The pre-existing resource is discovered and named <namespace>/<name>.
	waitFor(t, ctx, func() bool { _, ok := agent.desired()["preview-1/postgres"]; return ok })
	svc := agent.desired()["preview-1/postgres"]
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
	if _, ok := agent.desired()["preview-2/postgres"]; ok {
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

	// A tenant's DSN is not completed from the exit node's environment, so
	// one without a password is refused.
	create("preview-3", "postgres", map[string]any{
		"kind":        "postgres",
		"credentials": map[string]any{"dsnRef": map[string]any{"kubernetesSecret": map[string]any{"name": "db", "key": "dsn"}}},
	})
	invalid("preview-3", "postgres", "password")

	// A tenant cannot offer the cluster's own API.
	create("preview-2", "kubernetes", map[string]any{"kind": "kubernetes", "grantableRoles": []any{"system:masters"}})
	invalid("preview-2", "kubernetes", "only be registered in the exit node's namespace")
	if _, ok := agent.desired()["preview-2/kubernetes"]; ok {
		t.Error("a tenant's kubernetes service was defined")
	}

	// Deleting the resource withdraws its service.
	if err := dyn.Resource(TunnelServiceGVR).Namespace("preview-1").Delete(ctx, "postgres", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ctx, func() bool { _, ok := agent.desired()["preview-1/postgres"]; return !ok })
}

// TestDiscoveryQuotesNoSecret points TunnelServices at every key of a Secret,
// as someone may who can write TunnelServices but not read the Secret, and
// checks that nothing the keys hold reaches a status, an advertisement or the
// log.
func TestDiscoveryQuotesNoSecret(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// A Secret with many keys, as a database operator writes them. Each
	// value hides the marker wherever an error could quote it. Only "uri" is
	// a DSN, and its password must not show once it fails to connect.
	const marker = "zq7x"
	values := map[string]string{
		"password":        "zq7x-Adm1n-Passw0rd-zq7x",
		"pgpass":          "orders-rw:5432:orders:app:zq7x",
		"jdbc-uri":        "jdbc:postgresql://orders-rw:5432/orders?user=app&password=zq7x",
		"query-key":       "postgres://app:pw@orders-rw/orders?zq7x=1",
		"connect-timeout": "postgres://app:pw@orders-rw/orders?connect_timeout=zq7x",
		"sslmode":         "postgres://app:pw@orders-rw/orders?sslmode=zq7x",
		// A backtick, colon and space in the database, which is how pgx's
		// error ends its quote of the conninfo, and then a setting that fails.
		"cut": "postgres://app:pw@orders-rw/x%60%3A%20zq7x?sslmode=zq7x",
		"nul": "postgres://app:pw@orders-rw/orders%00zq7x",
		"uri": "postgres://app:zq7x@127.0.0.1:1/orders?sslmode=disable",
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "orders-app", Namespace: "shop"}, Data: map[string][]byte{}}
	for key, value := range values {
		secret.Data[key] = []byte(value)
	}

	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{TunnelServiceGVR: "TunnelServiceList"})
	var out syncBuffer
	log := slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug}))
	agent := &Agent{Log: log}
	d := &Discovery{Agent: agent, Namespace: "tunneler", Dynamic: dyn, Clients: k8sfake.NewSimpleClientset(secret), Log: log}
	go d.Run(ctx)

	for key := range values {
		ts := tunnelService("shop", key, map[string]any{
			"kind":        "postgres",
			"credentials": map[string]any{"dsnRef": map[string]any{"kubernetesSecret": map[string]any{"name": "orders-app", "key": key}}},
		})
		if _, err := dyn.Resource(TunnelServiceGVR).Namespace("shop").Create(ctx, ts, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, ctx, func() bool { _, ok := agent.desired()["shop/uri"]; return ok })
	agent.reconcile(ctx)

	for key := range values {
		want := "InvalidSpec"
		if key == "uri" {
			want = "Unreachable"
		}
		waitFor(t, ctx, func() bool { c := condition(t, ctx, dyn, "shop", key); return c != nil && c.Reason == want })
		if c := condition(t, ctx, dyn, "shop", key); strings.Contains(c.Message, marker) {
			t.Errorf("the status for key %q quotes the Secret: %s", key, c.Message)
		}
	}
	for _, advert := range *agent.adverts.Load() {
		if strings.Contains(advert.Status, marker) {
			t.Errorf("the advertisement of %s quotes the Secret: %s", advert.Name, advert.Status)
		}
	}
	if strings.Contains(out.String(), marker) {
		t.Errorf("the log quotes the Secret:\n%s", out.String())
	}
}

// syncBuffer is a log that the test reads while the exit node's goroutines
// write to it.
type syncBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

func TestDiscoveryKeyVault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Entra, which gives the exit node a token for any vault.
	entra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "vault-token", "token_type": "Bearer", "expires_in": 3600})
	}))
	defer entra.Close()
	file := filepath.Join(t.TempDir(), "token")
	os.WriteFile(file, []byte("projected-sa-token"), 0o600)
	t.Setenv("AZURE_CLIENT_ID", "exit-identity")
	t.Setenv("AZURE_TENANT_ID", "my-tenant")
	t.Setenv("AZURE_AUTHORITY_HOST", entra.URL+"/")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", file)
	azure, err := NewAzureCredential()
	if err != nil {
		t.Fatal(err)
	}

	// A vault for each of two teams. The exit node's one identity can read
	// both, as it must when both teams use Key Vault.
	vault := func(database string) (*httptest.Server, *atomic.Int32) {
		var fetches atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fetches.Add(1)
			json.NewEncoder(w).Encode(map[string]string{"value": "postgres://tunneler_admin:pw@127.0.0.1:1/" + database + "?sslmode=disable"})
		}))
		t.Cleanup(srv.Close)
		return srv, &fetches
	}
	vaultA, fetchesA := vault("a")
	vaultB, fetchesB := vault("b")
	allowed, err := ParseKeyVaultSecrets([]string{
		"team-a=" + vaultA.URL + "/secrets/tunneler-db-uri",
		"team-b=" + vaultB.URL + "/secrets/tunneler-db-uri",
	})
	if err != nil {
		t.Fatal(err)
	}
	keyVault := func(vaultURI string) map[string]any {
		return map[string]any{
			"kind": "postgres",
			"credentials": map[string]any{"dsnRef": map[string]any{
				"azureKeyVault": map[string]any{"vaultUri": vaultURI, "secretName": "tunneler-db-uri"},
			}},
		}
	}

	// Team A's own secret, with its vault URI spelled differently.
	own := tunnelService("team-a", "postgres", keyVault("HTTP"+strings.TrimPrefix(vaultA.URL, "http")+"/"))
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{TunnelServiceGVR: "TunnelServiceList"}, own)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent := &Agent{Log: log}
	d := &Discovery{Agent: agent, Namespace: "tunneler", Dynamic: dyn, Clients: k8sfake.NewSimpleClientset(),
		Azure: azure, KeyVaultSecrets: allowed, Log: log}
	go d.Run(ctx)

	waitFor(t, ctx, func() bool { _, ok := agent.desired()["team-a/postgres"]; return ok })
	if got := agent.desired()["team-a/postgres"].advert.Database; got != "a" || fetchesA.Load() == 0 {
		t.Errorf("team A's service is on database %q after %d fetches from its vault", got, fetchesA.Load())
	}

	// Team B's secret, named by team A or by a namespace with no secrets
	// listed, is refused before anything is fetched from team B's vault.
	for _, ns := range []string{"team-a", "team-c"} {
		if _, err := dyn.Resource(TunnelServiceGVR).Namespace(ns).
			Create(ctx, tunnelService(ns, "stolen", keyVault(vaultB.URL)), metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		waitFor(t, ctx, func() bool {
			_, defined := agent.desired()[ns+"/stolen"]
			return defined || condition(t, ctx, dyn, ns, "stolen") != nil
		})
		if _, ok := agent.desired()[ns+"/stolen"]; ok {
			t.Errorf("%s was offered a service built from team B's secret", ns)
		}
		c := condition(t, ctx, dyn, ns, "stolen")
		if c == nil || c.Reason != "InvalidSpec" || !strings.Contains(c.Message, "--key-vault-secret "+ns+"="+vaultB.URL+"/secrets/tunneler-db-uri") {
			t.Errorf("%s naming team B's secret: condition = %+v", ns, c)
		}
	}
	if n := fetchesB.Load(); n != 0 {
		t.Errorf("team B's vault was asked for its secret %d times for other namespaces", n)
	}
}

// A vault that never answers, or answers with more than any secret, fails
// only the resource that names it, and holds up the others' events for no
// longer than the timeout.
func TestDiscoveryKeyVaultBounded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	azure, _ := fakeEntra(t)

	// A vault that takes the request and never answers, and one whose answer
	// goes on for 256 MiB, as long as the exit node's memory limit.
	asked := make(chan struct{}, 1)
	silent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case asked <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
		case <-ctx.Done():
		}
	}))
	t.Cleanup(silent.Close)
	var sent atomic.Int64
	endless := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"value":"`)
		chunk := []byte(strings.Repeat("A", 64<<10))
		for written := 0; written < 256<<20; {
			n, err := w.Write(chunk)
			written += n
			sent.Add(int64(n))
			if err != nil {
				return
			}
		}
		io.WriteString(w, `"}`)
	}))
	t.Cleanup(endless.Close)
	allowed, err := ParseKeyVaultSecrets([]string{
		"team-a=" + silent.URL + "/secrets/tunneler-db-uri",
		"team-b=" + endless.URL + "/secrets/tunneler-db-uri",
	})
	if err != nil {
		t.Fatal(err)
	}
	keyVault := func(vaultURI string) map[string]any {
		return map[string]any{
			"kind": "postgres",
			"credentials": map[string]any{"dsnRef": map[string]any{
				"azureKeyVault": map[string]any{"vaultUri": vaultURI, "secretName": "tunneler-db-uri"},
			}},
		}
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "team-c"},
		Data:       map[string][]byte{"dsn": []byte("postgres://admin:pw@127.0.0.1:1/c?sslmode=disable")},
	}

	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{TunnelServiceGVR: "TunnelServiceList"},
		tunnelService("team-a", "postgres", keyVault(silent.URL)),
		tunnelService("team-b", "postgres", keyVault(endless.URL)))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent := &Agent{Log: log}
	d := &Discovery{Agent: agent, Namespace: "tunneler", Dynamic: dyn, Clients: k8sfake.NewSimpleClientset(secret),
		Azure: azure, KeyVaultSecrets: allowed, Log: log, credentialTimeout: time.Second}
	go d.Run(ctx)

	// Another team's resource, created while the exit node waits on the
	// silent vault, is still defined and withdrawn.
	select {
	case <-asked:
	case <-ctx.Done():
		t.Fatal("the silent vault was never asked")
	}
	if _, err := dyn.Resource(TunnelServiceGVR).Namespace("team-c").Create(ctx, tunnelService("team-c", "postgres", map[string]any{
		"kind":        "postgres",
		"credentials": map[string]any{"dsnRef": map[string]any{"kubernetesSecret": map[string]any{"name": "db", "key": "dsn"}}},
	}), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ctx, func() bool { _, ok := agent.desired()["team-c/postgres"]; return ok })
	if err := dyn.Resource(TunnelServiceGVR).Namespace("team-c").Delete(ctx, "postgres", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ctx, func() bool { _, ok := agent.desired()["team-c/postgres"]; return !ok })

	for ns, why := range map[string]string{"team-a": "no answer within 1s", "team-b": "larger than any secret"} {
		if c := condition(t, ctx, dyn, ns, "postgres"); c == nil || c.Reason != "CredentialsInvalid" || !strings.Contains(c.Message, why) {
			t.Errorf("%s: condition = %+v, want CredentialsInvalid saying %q", ns, c, why)
		}
	}
	// The endless vault is asked again when the status comes back as an
	// update. Each time, what it sends past the cap is only what fits in the
	// sockets' buffers, a few MiB at most.
	if n := sent.Load(); n > 64<<20 {
		t.Errorf("the endless vault sent %d MiB before the exit node stopped reading", n>>20)
	}
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

// Each resource's service has a name that no other resource can give. Joined
// with a hyphen, shared/db passed for the operator's shared-db, team/a-db for
// team-a/db, and shop/postgres-main for shop-postgres/main, and whichever
// the informer listed first took the name.
func TestDiscoveryNamesAreDistinct(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resources := []struct{ namespace, name, service string }{
		{"tunneler", "shared-db", "shared-db"},
		{"shared", "db", "shared/db"},
		{"team", "a-db", "team/a-db"},
		{"team-a", "db", "team-a/db"},
		{"shop", "postgres-main", "shop/postgres-main"},
		{"shop-postgres", "main", "shop-postgres/main"},
	}
	var objects, secrets []runtime.Object
	want := make(map[string]string) // the namespace of each service's resource, by service name
	for _, r := range resources {
		objects = append(objects, tunnelService(r.namespace, r.name, map[string]any{
			"kind":        "postgres",
			"credentials": map[string]any{"dsnRef": map[string]any{"kubernetesSecret": map[string]any{"name": "db", "key": "dsn"}}},
		}))
		secrets = append(secrets, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: r.namespace},
			Data:       map[string][]byte{"dsn": []byte("postgres://admin:pw@127.0.0.1:1/" + r.namespace + "?sslmode=disable")},
		})
		want[r.service] = r.namespace
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{TunnelServiceGVR: "TunnelServiceList"}, objects...)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent := &Agent{Log: log}
	d := &Discovery{Agent: agent, Namespace: "tunneler", Dynamic: dyn, Clients: k8sfake.NewSimpleClientset(secrets...), Log: log}
	go d.Run(ctx)

	got := func() map[string]string {
		out := make(map[string]string)
		for name, svc := range agent.desired() {
			out[name] = svc.advert.Labels["namespace"]
		}
		return out
	}
	for !maps.Equal(got(), want) && ctx.Err() == nil {
		time.Sleep(20 * time.Millisecond)
	}
	if !maps.Equal(got(), want) {
		t.Errorf("namespace of each service's resource = %v, want %v", got(), want)
	}
}
