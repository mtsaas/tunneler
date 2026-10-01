package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func TestServerLoggerKeepsTargetServiceSeparate(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	original := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = original }()

	logger := newLogger(true, false)
	logger.Info("service reachable", "target_service", "orders")
	logger.With("audit", true).Info("query", "target_service", "orders")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d log records: %s", len(lines), output)
	}
	for _, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if _, exists := record["service"]; exists || record["target_service"] != "orders" {
			t.Errorf("service fields = %v", record)
		}
	}
}
