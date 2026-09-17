package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
)

func message(typ byte, body string) []byte {
	return append(binary.BigEndian.AppendUint32([]byte{typ}, uint32(len(body)+4)), body...)
}

func startup(params ...string) []byte {
	body := binary.BigEndian.AppendUint32(nil, 3<<16)
	for _, p := range params {
		body = append(append(body, p...), 0)
	}
	body = append(body, 0)
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(body)+4)), body...)
}

func TestRelayAudits(t *testing.T) {
	big := strings.Repeat("x", maxAuditLen+100)
	in := slices.Concat(
		message('p', "hunter2\x00"), // a password must pass through unlogged
		message('Q', "SELECT 1\x00"),
		message('P', "stmt\x00SELECT $1\x00\x00\x00"),
		message('d', "copy data Q P"),
		message('Q', big+"\x00"),
		message('X', ""),
	)
	var out bytes.Buffer
	var got []string
	err := relay(&out, bytes.NewReader(in), func(q string) { got = append(got, q) })
	if err != io.EOF {
		t.Fatalf("relay: %v", err)
	}
	if !bytes.Equal(out.Bytes(), in) {
		t.Error("relay altered the stream")
	}
	want := []string{"SELECT 1", "SELECT $1", big[:maxAuditLen] + " [truncated]"}
	if !slices.Equal(got, want) {
		t.Errorf("audited %q, want %q", got, want)
	}
}

func TestProxyConfinesLogin(t *testing.T) {
	for _, tt := range []struct {
		name   string
		params []string
	}{
		{"other role", []string{"user", "postgres", "database", "app"}},
		{"other database", []string{"user", "tnl_me", "database", "postgres"}},
	} {
		client, server := net.Pipe()
		dialed := false
		done := make(chan error, 1)
		go func() {
			done <- Proxy(context.Background(), server, func(context.Context) (net.Conn, error) {
				dialed = true
				return nil, io.ErrUnexpectedEOF
			}, "tnl_me", "app", func(string) {})
		}()

		// An SSLRequest first, as libpq sends by default; it must be declined.
		client.Write(binary.BigEndian.AppendUint32([]byte{0, 0, 0, 8}, codeSSL))
		var resp [1]byte
		io.ReadFull(client, resp[:])
		if resp[0] != 'N' {
			t.Fatalf("%s: SSLRequest answered %q, want N", tt.name, resp[0])
		}
		go client.Write(startup(tt.params...))
		reply, _ := io.ReadAll(client)
		if err := <-done; err == nil || dialed {
			t.Errorf("%s: err = %v, dialed upstream = %v; want refusal before dialing", tt.name, err, dialed)
		}
		if len(reply) == 0 || reply[0] != 'E' {
			t.Errorf("%s: client got %q, want an ErrorResponse", tt.name, reply)
		}
	}
}
