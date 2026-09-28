package postgres

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestConnectCancelsStalledTLSNegotiation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	s, err := NewServer("postgres://admin:pw@" + listener.Addr().String() + "/app?sslmode=require")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, err := s.Connect(ctx)
		if conn != nil {
			conn.Close()
		}
		result <- err
	}()
	server := <-accepted
	defer server.Close()
	var sslRequest [8]byte
	if _, err := io.ReadFull(server, sslRequest[:]); err != nil {
		t.Fatal(err)
	}
	// The server accepts the SSL request and sends no response.
	select {
	case err := <-result:
		if err == nil || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("Connect = %v; context = %v, want cancellation of the stalled read", err, ctx.Err())
		}
	case <-time.After(time.Second):
		t.Error("Connect remained blocked after its context expired")
	}
}
