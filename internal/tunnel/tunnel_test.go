package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// echo accepts a stream and echoes it back.
func echo(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer ok" {
		http.Error(w, "who are you", http.StatusUnauthorized)
		return
	}
	conn, err := Accept(w, r)
	if err != nil {
		return
	}
	defer conn.Close()
	io.Copy(conn, conn)
}

func TestStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(echo))
	defer srv.Close()

	conn, err := Dial(context.Background(), srv.URL, http.Header{"Authorization": {"Bearer ok"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Larger than any default WebSocket message limit, to prove it is a stream.
	want := bytes.Repeat([]byte("tunneler"), 1<<17)
	go conn.Write(want)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("echo of %d bytes: %v", len(want), err)
	}

	_, err = Dial(context.Background(), srv.URL, nil)
	var status *StatusError
	if !errors.As(err, &status) || status.Code != http.StatusUnauthorized || !strings.Contains(status.Body, "who are you") {
		t.Errorf("unauthorized dial: %v", err)
	}
}

// TestLegacyClient speaks the pre-WebSocket handshake, as older exit nodes
// and clients do.
func TestLegacyClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(echo))
	defer srv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: tunneler\r\nAuthorization: Bearer ok\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("handshake: %v %v", resp, err)
	}
	fmt.Fprint(conn, "hello")
	got := make([]byte, 5)
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "hello" {
		t.Fatalf("echo = %q, %v", got, err)
	}
}
