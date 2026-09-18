// Package e2e runs tunneler in a kind cluster. The tests need docker, kind,
// helm and kubectl, take minutes, and run only with TUNNELER_KIND=1:
//
//	TUNNELER_KIND=1 go test -count=1 -timeout 15m ./e2e/
//
// The cluster is left running for inspection and reused by later runs;
// remove it with: kind delete cluster --name tunneler
package e2e

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const cluster = "tunneler"

var tunnelServiceGVR = schema.GroupVersionResource{Group: "tunneler.marconet.com", Version: "v1alpha1", Resource: "tunnelservices"}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	t.Logf("$ %s %s", name, strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	cmd.Dir = ".."
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s %s: %v", name, strings.Join(args, " "), err)
	}
	return string(out)
}

// TestKindExitAuth checks the exit node's authentication to the coordinator
// with a real Kubernetes issuer: a projected service account token from the
// right service account is accepted and binds the cluster name, one from
// another service account is rejected, and the accepted node goes on to
// discover a TunnelService and report it Ready.
func TestKindExitAuth(t *testing.T) {
	if os.Getenv("TUNNELER_KIND") == "" {
		t.Skip("TUNNELER_KIND not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if !strings.Contains(run(t, "kind", "get", "clusters"), cluster) {
		run(t, "kind", "create", "cluster", "--name", cluster, "--wait", "120s")
	}
	run(t, "docker", "build", "-q", "-t", "tunneler:e2e", ".")
	run(t, "kind", "load", "docker-image", "tunneler:e2e", "--name", cluster)
	kubectl := func(args ...string) string {
		return run(t, "kubectl", append([]string{"--context", "kind-" + cluster}, args...)...)
	}
	// Install with the published charts, so that they are what is tested.
	helm := func(release, chart, values string) {
		run(t, "helm", "--kube-context", "kind-"+cluster, "upgrade", "--install", release, chart,
			"--namespace", "tunneler", "--create-namespace", "--values", values)
	}
	// Helm installs a chart's CRDs once and never upgrades them, so a cluster
	// reused from an earlier run needs the current definition applied.
	kubectl("apply", "--server-side", "-f", "charts/tunneler-exit/crds")
	helm("tunneler-coordinator", "charts/tunneler-coordinator", "hack/kind/coordinator-values.yaml")
	helm("tunneler-exit", "charts/tunneler-exit", "hack/kind/exit-values.yaml")
	kubectl("apply", "-f", "hack/kind/manifests.yaml", "-f", "hack/kind/impostor.yaml")
	// A fresh binding and fresh logs on every run.
	kubectl("-n", "tunneler", "rollout", "restart", "statefulset/tunneler-coordinator", "deployment/tunneler-exit", "deployment/tunneler-impostor")
	kubectl("-n", "tunneler", "rollout", "status", "statefulset/tunneler-coordinator", "--timeout=240s")
	kubectl("-n", "tunneler", "rollout", "status", "deployment/postgres", "--timeout=240s")
	kubectl("-n", "tunneler", "rollout", "status", "deployment/tunneler-exit", "--timeout=240s")

	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{CurrentContext: "kind-" + cluster}).ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	dyn, clients := dynamic.NewForConfigOrDie(cfg), kubernetes.NewForConfigOrDie(cfg)

	// The genuine exit node authenticates, and its service becomes Ready.
	var ready, reason string
	for ready != "True" && ctx.Err() == nil {
		time.Sleep(2 * time.Second)
		ts, err := dyn.Resource(tunnelServiceGVR).Namespace("tunneler").Get(ctx, "postgres", metav1.GetOptions{})
		if err != nil {
			continue
		}
		conditions, _, _ := unstructured.NestedSlice(ts.Object, "status", "conditions")
		for _, c := range conditions {
			cond, _ := c.(map[string]any)
			if cond["type"] == "Ready" {
				ready, _ = cond["status"].(string)
				reason, _ = cond["reason"].(string)
			}
		}
	}
	if ready != "True" {
		t.Fatalf("TunnelService never became Ready (last reason %q)", reason)
	}

	// The coordinator's log tells the story: the right node was admitted and
	// bound the name, the impostor was refused for its subject.
	var log string
	for ctx.Err() == nil && (!strings.Contains(log, "exit node connected") || !strings.Contains(log, "not exit_subject")) {
		time.Sleep(2 * time.Second)
		log = coordinatorLog(t, ctx, clients)
	}
	for _, want := range []string{
		`"msg":"exit node connected; its services are now routable","cluster":"kind"`,
		`"cluster":"kind"`, "system:serviceaccount:tunneler:default", "not exit_subject",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("coordinator log lacks %q", want)
		}
	}
	if t.Failed() {
		t.Log(log)
	}
}

func coordinatorLog(t *testing.T, ctx context.Context, clients *kubernetes.Clientset) string {
	t.Helper()
	pods, err := clients.CoreV1().Pods("tunneler").List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=tunneler-coordinator"})
	if err != nil || len(pods.Items) == 0 {
		return ""
	}
	var newest corev1.Pod
	for _, p := range pods.Items {
		if p.CreationTimestamp.After(newest.CreationTimestamp.Time) {
			newest = p
		}
	}
	stream, err := clients.CoreV1().Pods("tunneler").GetLogs(newest.Name, &corev1.PodLogOptions{}).Stream(ctx)
	if err != nil {
		return ""
	}
	defer stream.Close()
	b, _ := io.ReadAll(stream)
	return string(b)
}

// TestKindKubectl runs the real kubectl through the tunnel: to a coordinator
// in the cluster, through the exit node, to the cluster's own API server.
// It runs after TestKindExitAuth, which deploys everything.
func TestKindKubectl(t *testing.T) {
	if os.Getenv("TUNNELER_KIND") == "" {
		t.Skip("TUNNELER_KIND not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	admin := func(args ...string) string {
		return run(t, "kubectl", append([]string{"--context", "kind-" + cluster}, args...)...)
	}
	for ready := ""; ready != "True" && ctx.Err() == nil; time.Sleep(2 * time.Second) {
		out, _ := exec.Command("kubectl", "--context", "kind-"+cluster, "-n", "tunneler", "get", "tunnelservice", "kubernetes",
			"-o", `jsonpath={.status.conditions[?(@.type=="Ready")].status}`).Output()
		ready = string(out)
	}

	// Reach the coordinator from here, as a laptop would over the internet.
	forward := exec.CommandContext(ctx, "kubectl", "--context", "kind-"+cluster, "-n", "tunneler",
		"port-forward", "service/tunneler-coordinator", "18443:8443")
	if err := forward.Start(); err != nil {
		t.Fatal(err)
	}
	defer forward.Process.Kill()

	// kubectl sends credentials only over TLS, which in production an ingress
	// provides in front of the coordinator. Here, this does.
	upstream, _ := url.Parse("http://127.0.0.1:18443")
	front := httputil.NewSingleHostReverseProxy(upstream)
	front.FlushInterval = -1
	ingress := httptest.NewTLSServer(front)
	defer ingress.Close()
	ca := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ingress.Certificate().Raw}))

	// A kubeconfig that knows only the coordinator, and a login.
	token := strings.TrimSpace(admin("-n", "tunneler", "create", "token", "e2e-user", "--audience", "tunneler-users", "--duration", "1h"))
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	os.WriteFile(kubeconfig, []byte(`apiVersion: v1
kind: Config
current-context: tunneler
clusters: [{name: tunneler, cluster: {server: "`+ingress.URL+`/v1/gateway/kind/kubernetes", certificate-authority-data: "`+ca+`"}}]
users: [{name: me, user: {token: "`+token+`"}}]
contexts: [{name: tunneler, context: {cluster: tunneler, user: me, namespace: tunneler}}]
`), 0o600)
	kubectl := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "kubectl", append([]string{"--kubeconfig", kubeconfig}, args...)...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	var out string
	var err error
	for ctx.Err() == nil { // until the port-forward is up
		if out, err = kubectl("get", "pods"); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil || !strings.Contains(out, "tunneler-coordinator-0") {
		t.Fatalf("kubectl get pods: %v\n%s", err, out)
	}

	// The cluster knows the person by the identity the coordinator gave, and
	// its own RBAC decides what they may do.
	if out, err := kubectl("auth", "whoami", "-o", "jsonpath={.status.userInfo.groups}"); err != nil || !strings.Contains(out, "tunneler:view") {
		t.Errorf("kubectl auth whoami: %v\n%s", err, out)
	}
	if out, err := kubectl("delete", "pod", "tunneler-coordinator-0"); err == nil || !strings.Contains(out, "forbidden") {
		t.Errorf("deleting a pod with only view: %v\n%s", err, out)
	}
	// Someone with no grant is told why, in words kubectl can show.
	nobody := strings.TrimSpace(admin("-n", "tunneler", "create", "token", "default", "--audience", "tunneler-users", "--duration", "10m"))
	if out, err := kubectl("--token", nobody, "get", "pods"); err == nil || !strings.Contains(out, "tunneler auth status") {
		t.Errorf("kubectl without a grant: %v\n%s", err, out)
	}
	if out, err := kubectl("get", "secrets"); err == nil || !strings.Contains(out, "forbidden") {
		t.Errorf("view does not include secrets, yet: %v\n%s", err, out)
	}

	// exec upgrades the connection, through the ingress-less path here:
	// kubectl, the gateway, the tunnel, the exit node, the API server.
	if out, err := kubectl("exec", "deployment/postgres", "--", "echo", "hello from the pod"); err != nil || !strings.Contains(out, "hello from the pod") {
		t.Errorf("kubectl exec: %v\n%s", err, out)
	}
	// A watch streams.
	watch := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kubeconfig, "get", "pods", "--watch", "--request-timeout=5s")
	if out, _ := watch.CombinedOutput(); !strings.Contains(string(out), "tunneler-coordinator-0") {
		t.Errorf("kubectl get --watch:\n%s", out)
	}

	// All of it is on the coordinator's audit trail.
	log := admin("-n", "tunneler", "logs", "statefulset/tunneler-coordinator")
	for _, want := range []string{`"msg":"kubernetes request"`, `"resource":"pods"`, `"subresource":"exec"`, `"command":["echo","hello from the pod"]`, `"verb":"delete"`, `"status":403`} {
		if !strings.Contains(log, want) {
			t.Errorf("audit trail lacks %s", want)
		}
	}
}
