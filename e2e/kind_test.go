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
	"io"
	"os"
	"os/exec"
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
