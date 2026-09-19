package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

// TestSession opens a stream each way over one connection, and checks what
// the exit node protocol relies on: a message is read without reading past
// its end, and Close unblocks a Read in progress, as net.Conn promises.
func TestSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	accepted := make(chan *Session, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := Accept(w, r)
		if err != nil {
			return
		}
		s := Server(conn, log)
		accepted <- s
		<-s.Done()
	}))
	defer srv.Close()
	conn, err := Dial(ctx, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := Client(conn, log)
	defer client.Close()
	server := <-accepted
	defer server.Close()

	for _, way := range []struct {
		name         string
		open, accept *Session
	}{{"client to server", client, server}, {"server to client", server, client}} {
		out, err := way.open.Open()
		if err != nil {
			t.Fatalf("%s: %v", way.name, err)
		}
		if err := WriteMessage(out, map[string]string{"op": "dial"}); err != nil {
			t.Fatalf("%s: %v", way.name, err)
		}
		out.Write([]byte("after"))
		in, err := way.accept.Accept(ctx)
		if err != nil {
			t.Fatalf("%s: %v", way.name, err)
		}
		var msg map[string]string
		after := make([]byte, 5)
		if err := ReadMessage(in, &msg); err != nil || msg["op"] != "dial" {
			t.Errorf("%s: message = %v, %v", way.name, msg, err)
		} else if _, err := io.ReadFull(in, after); err != nil || string(after) != "after" {
			t.Errorf("%s: what followed the message = %q, %v", way.name, after, err)
		}
	}

	// The peer never closes this stream, and never even accepts it.
	idle, err := client.Open()
	if err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	go func() {
		_, err := idle.Read(make([]byte, 1))
		read <- err
	}()
	time.Sleep(20 * time.Millisecond) // let the Read block
	idle.Close()
	select {
	case err := <-read:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Read after Close = %v, want net.ErrClosed", err)
		}
	case <-ctx.Done():
		t.Fatal("Close did not unblock a Read in progress")
	}
}
