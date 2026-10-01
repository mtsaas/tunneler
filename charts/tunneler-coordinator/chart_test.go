package coordinatorchart

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mtsaas/tunneler/internal/coordinator"
	"go.yaml.in/yaml/v3"
)

type manifest struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name        string            `yaml:"name"`
		Namespace   string            `yaml:"namespace"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
	Data map[string]string `yaml:"data"`
	Spec map[string]any    `yaml:"spec"`
}

func chartValues() map[string]any {
	return map[string]any{"config": map[string]any{
		"oidc":         map[string]any{"issuer": "https://issuer.example.test", "client_id": "chart-test"},
		"exit_issuers": []string{"https://exit.example.test"},
	}}
}

func sharingValues() map[string]any {
	return map[string]any{
		"domain": "preview.example.net", "control_hosts": []string{"control.example.com"},
		"allow_authenticated":            true,
		"max_operation_records_per_user": 32,
	}
}

func renderChart(t *testing.T, values map[string]any) ([]manifest, string, error) {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv("TUNNELER_REQUIRE_HELM_TESTS") == "1" {
			t.Fatal("Helm is required for chart validation in CI")
		}
		t.Skip("install Helm to run chart render tests")
	}
	data, err := yaml.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(helm, "template", "chart-test", ".", "--namespace", "sharing-test", "--values", path)
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, string(output), err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(output))
	var manifests []manifest
	for {
		var document manifest
		if err := decoder.Decode(&document); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("decode rendered manifest: %v", err)
		}
		if document.Kind != "" {
			if document.Metadata.Namespace != "sharing-test" {
				t.Fatalf("%s/%s does not target the release namespace: %q", document.Kind, document.Metadata.Name, document.Metadata.Namespace)
			}
			manifests = append(manifests, document)
		}
	}
	return manifests, string(output), nil
}

func findManifest(t *testing.T, manifests []manifest, kind, name string) manifest {
	t.Helper()
	for _, document := range manifests {
		if document.Kind == kind && document.Metadata.Name == name {
			return document
		}
	}
	t.Fatalf("missing %s/%s", kind, name)
	return manifest{}
}

func loadRenderedConfig(t *testing.T, manifests []manifest) (*coordinator.Config, error) {
	t.Helper()
	config := findManifest(t, manifests, "ConfigMap", "chart-test").Data["config.json"]
	if !json.Valid([]byte(config)) {
		t.Fatal("rendered configuration is not JSON")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return coordinator.LoadConfig(path)
}

func TestChartSharingWithOwnTLSEdgePreservesDeployment(t *testing.T) {
	baseline, output, err := renderChart(t, chartValues())
	if err != nil {
		t.Fatalf("existing chart: %v\n%s", err, output)
	}
	config, err := loadRenderedConfig(t, baseline)
	if err != nil || config.Sharing != nil {
		t.Fatalf("existing configuration changed: %+v %v", config, err)
	}
	for _, document := range baseline {
		if document.Kind == "Ingress" {
			t.Fatal("ingress appeared in an existing installation")
		}
	}
	for _, restricted := range []bool{false, true} {
		values := chartValues()
		sharing := sharingValues()
		if restricted {
			sharing["allow_authenticated"] = false
			sharing["grants"] = []map[string]any{{"user": "publisher"}, {"group": "developers"}}
		}
		values["config"].(map[string]any)["sharing"] = sharing
		manifests, output, err := renderChart(t, values)
		if err != nil {
			t.Fatalf("sharing with ingress disabled: %v\n%s", err, output)
		}
		config, err := loadRenderedConfig(t, manifests)
		if err != nil {
			t.Fatalf("rendered sharing configuration: %v", err)
		}
		if config.Sharing == nil || config.Sharing.Domain != "preview.example.net" || config.Sharing.AllowAuthenticated == restricted || len(config.Sharing.ControlHosts) != 1 || config.Sharing.ControlHosts[0] != "control.example.com" {
			t.Fatalf("sharing configuration lost values: %+v", config.Sharing)
		}
		if restricted && len(config.Sharing.Grants) != 2 {
			t.Fatalf("publishing grants lost: %+v", config.Sharing.Grants)
		}
		if config.Sharing.MaxOperationRecordsPerUser != 32 {
			t.Fatalf("retained operation budget lost: %+v", config.Sharing)
		}
		for _, document := range manifests {
			if document.Kind == "Ingress" {
				t.Fatal("bring-your-own-edge values rendered an Ingress")
			}
		}
		for _, kind := range []string{"Service", "StatefulSet"} {
			before := findManifest(t, baseline, kind, "chart-test")
			after := findManifest(t, manifests, kind, "chart-test")
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("sharing changed the existing %s", kind)
			}
		}
	}
}

func TestChartPreviewIngressRoutesAndNamespacedTLS(t *testing.T) {
	values := chartValues()
	values["config"].(map[string]any)["sharing"] = sharingValues()
	values["ingress"] = map[string]any{
		"enabled": true, "className": "edge", "host": "control.example.com", "tlsSecretName": "control-tls",
		"annotations": map[string]string{"example.com/control": "yes"},
		"preview":     map[string]any{"enabled": true, "tlsSecretName": "preview-tls", "annotations": map[string]string{"example.com/streaming": "yes"}},
	}
	manifests, output, err := renderChart(t, values)
	if err != nil {
		t.Fatalf("preview ingress: %v\n%s", err, output)
	}
	if _, err := loadRenderedConfig(t, manifests); err != nil {
		t.Fatalf("ingress sharing configuration: %v", err)
	}
	for _, ingress := range []struct{ name, host, secret, annotation string }{
		{"chart-test", "control.example.com", "control-tls", "example.com/control"},
		{"chart-test-preview", "*.preview.example.net", "preview-tls", "example.com/streaming"},
	} {
		document := findManifest(t, manifests, "Ingress", ingress.name)
		if document.APIVersion != "networking.k8s.io/v1" || document.Metadata.Namespace != "sharing-test" {
			t.Fatalf("ingress does not target the release namespace: %+v", document.Metadata)
		}
		if len(document.Metadata.Annotations) != 1 || document.Metadata.Annotations[ingress.annotation] != "yes" {
			t.Fatalf("ingress annotations leaked between routes: %+v", document.Metadata.Annotations)
		}
		wanted := map[string]any{
			"ingressClassName": "edge",
			"tls":              []any{map[string]any{"hosts": []any{ingress.host}, "secretName": ingress.secret}},
			"rules": []any{map[string]any{"host": ingress.host, "http": map[string]any{"paths": []any{map[string]any{
				"path": "/", "pathType": "Prefix", "backend": map[string]any{"service": map[string]any{"name": "chart-test", "port": map[string]any{"name": "http"}}},
			}}}}},
		}
		if !reflect.DeepEqual(document.Spec, wanted) {
			t.Fatalf("incorrect %s route/TLS: %+v", ingress.name, document.Spec)
		}
	}
}

func TestChartRejectsInvalidSharingValues(t *testing.T) {
	for _, test := range []struct {
		name  string
		field string
		value any
	}{
		{"missing domain", "domain", nil}, {"uppercase domain", "domain", "Preview.example.net"},
		{"domain URL", "domain", "https://preview.example.net"}, {"wildcard domain", "domain", "*.preview.example.net"},
		{"trailing dot", "domain", "preview.example.net."}, {"empty label", "domain", "preview..example.net"},
		{"oversized label", "domain", strings.Repeat("a", 64) + ".net"},
		{"oversized domain", "domain", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + ".net"},
		{"IP domain", "domain", "127.0.0.1"},
		{"missing control hosts", "control_hosts", nil}, {"empty control hosts", "control_hosts", []string{}},
		{"control hosts string", "control_hosts", "control.example.com"}, {"empty control authority", "control_hosts", []string{""}},
		{"control authority URL", "control_hosts", []string{"https://control.example.com"}},
		{"wildcard control authority", "control_hosts", []string{"*.example.com"}},
		{"string boolean", "allow_authenticated", "true"},
		{"multiple principals", "grants", []map[string]any{{"user": "alice", "group": "developers"}}},
		{"missing principal", "grants", []map[string]any{{}}}, {"empty principal", "grants", []map[string]any{{"user": ""}}},
		{"numeric principal", "grants", []map[string]any{{"group": 42}}},
		{"unknown option", "allow_authentication", true},
		{"negative limit", "max_connections", -1}, {"fractional limit", "max_connections", 1.5}, {"too many services", "max_services", 65},
		{"negative owner operation limit", "max_operation_records_per_user", -1},
		{"numeric duration", "authorization_lease", 90}, {"negative duration", "default_ttl", "-1h"}, {"invalid duration", "max_ttl", "forever"},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := chartValues()
			sharing := sharingValues()
			if test.value == nil {
				delete(sharing, test.field)
			} else {
				sharing[test.field] = test.value
			}
			values["config"].(map[string]any)["sharing"] = sharing
			_, output, err := renderChart(t, values)
			if err == nil || !strings.Contains(output, test.field) {
				t.Fatalf("invalid %s was not diagnosed before deployment: %v\n%s", test.field, err, output)
			}
		})
	}
	for _, value := range []any{false, "enabled", []string{"preview.example.net"}} {
		values := chartValues()
		values["config"].(map[string]any)["sharing"] = value
		if _, output, err := renderChart(t, values); err == nil || !strings.Contains(output, "sharing") {
			t.Fatalf("invalid sharing object was accepted: %v\n%s", err, output)
		}
	}
}

func TestChartRejectsIncompletePreviewIngress(t *testing.T) {
	for _, test := range []struct {
		name    string
		change  func(map[string]any, map[string]any, map[string]any)
		message string
	}{
		{"missing sharing", func(v, _, _ map[string]any) { delete(v["config"].(map[string]any), "sharing") }, "sharing"},
		{"disabled control ingress", func(_, i, _ map[string]any) { i["enabled"] = false }, "enabled"},
		{"missing preview TLS", func(_, _, p map[string]any) { delete(p, "tlsSecretName") }, "tlsSecretName"},
		{"empty preview TLS", func(_, _, p map[string]any) { p["tlsSecretName"] = "" }, "tlsSecretName"},
		{"invalid preview TLS name", func(_, _, p map[string]any) { p["tlsSecretName"] = "Preview/TLS" }, "tlsSecretName"},
		{"invalid preview TLS label", func(_, _, p map[string]any) { p["tlsSecretName"] = "preview..tls" }, "tlsSecretName"},
		{"string preview switch", func(_, _, p map[string]any) { p["enabled"] = "true" }, "enabled"},
		{"non-string annotations", func(_, _, p map[string]any) { p["annotations"] = map[string]any{"example.com/streaming": true} }, "annotations"},
		{"control host outside allowlist", func(_, i, _ map[string]any) { i["host"] = "other.example.com" }, "control_hosts"},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := chartValues()
			values["config"].(map[string]any)["sharing"] = sharingValues()
			preview := map[string]any{"enabled": true, "tlsSecretName": "preview-tls"}
			ingress := map[string]any{"enabled": true, "host": "control.example.com", "preview": preview}
			values["ingress"] = ingress
			test.change(values, ingress, preview)
			if _, output, err := renderChart(t, values); err == nil || !strings.Contains(output, test.message) {
				t.Fatalf("invalid preview ingress was not diagnosed: %v\n%s", err, output)
			}
		})
	}
}

func TestChartRenderedConfigUsesRuntimeDomainIsolation(t *testing.T) {
	values := chartValues()
	sharing := sharingValues()
	sharing["domain"] = "preview.example.com"
	values["config"].(map[string]any)["sharing"] = sharing
	manifests, output, err := renderChart(t, values)
	if err != nil {
		t.Fatalf("render domain-isolation fixture: %v\n%s", err, output)
	}
	if _, err := loadRenderedConfig(t, manifests); err == nil || !strings.Contains(err.Error(), "registrable domain") {
		t.Fatalf("runtime accepted domains sharing parent cookies: %v", err)
	}
}
