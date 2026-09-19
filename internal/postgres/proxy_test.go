package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
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

// fastPathCall is a FunctionCall message that runs pg_notify, OID 3036,
// outside any statement.
func fastPathCall(t *testing.T) []byte {
	msg, err := (&pgproto3.FunctionCall{Function: 3036, Arguments: [][]byte{[]byte("orders"), []byte("ran")}}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestRelayAudits(t *testing.T) {
	// However much filler comes first, the statement is recorded whole.
	hidden := "/*" + strings.Repeat(" ", 64<<10) + "*/ DROP TABLE orders"
	in := slices.Concat(
		message('p', "hunter2\x00"), // a password must pass through unlogged
		message('Q', "SELECT 1\x00"),
		message('P', "stmt\x00SELECT $1\x00\x00\x00"),
		message('d', "copy data Q P"),
		message('Q', hidden+"\x00"),
		message('X', ""),
	)
	var out bytes.Buffer
	var got []string
	err := relay(&out, bytes.NewReader(in), func(q string) error {
		got = append(got, q)
		return nil
	})
	if err != io.EOF {
		t.Fatalf("relay: %v", err)
	}
	if !bytes.Equal(out.Bytes(), in) {
		t.Error("relay altered the stream")
	}
	want := []string{"SELECT 1", "SELECT $1", hidden}
	if !slices.Equal(got, want) {
		t.Errorf("audited %q, want %q", got, want)
	}
}

// TestRelayRefuses sends, after a statement, a message whose work the trail
// could not show in full. The statement is recorded and reaches the server;
// not a byte of the refused message does.
func TestRelayRefuses(t *testing.T) {
	long := strings.Repeat(" ", maxStatementLen) + "DROP TABLE orders"
	for _, tt := range []struct {
		name string
		msg  []byte
		want error
	}{
		{"FunctionCall", fastPathCall(t), errFunctionCall},
		{"long Query", message('Q', long+"\x00"), errTooLong},
		{"long Parse", message('P', "\x00"+long+"\x00\x00\x00"), errTooLong},
	} {
		first := message('Q', "SELECT 1\x00")
		in := slices.Concat(first, tt.msg, message('Q', "SELECT 2\x00"))
		var out bytes.Buffer
		var got []string
		err := relay(&out, bytes.NewReader(in), func(q string) error {
			got = append(got, q)
			return nil
		})
		if err != tt.want {
			t.Errorf("%s: relay: %v, want %v", tt.name, err, tt.want)
		}
		if !bytes.Equal(out.Bytes(), first) {
			t.Errorf("%s: the server got %d bytes, want only the recorded statement's %d", tt.name, out.Len(), len(first))
		}
		if !slices.Equal(got, []string{"SELECT 1"}) {
			t.Errorf("%s: audited %d statements, want only SELECT 1", tt.name, len(got))
		}
	}
}

// TestProxyTellsClientOfRefusal has Proxy refuse a message. The client reads
// an ErrorResponse that says why, and the server gets nothing after the
// startup packet.
func TestProxyTellsClientOfRefusal(t *testing.T) {
	for _, tt := range []struct {
		name     string
		msg      []byte
		sqlstate string
	}{
		{"FunctionCall", fastPathCall(t), "0A000"},
		{"long statement", message('Q', strings.Repeat(" ", maxStatementLen)+"DROP TABLE orders\x00"), "54000"},
	} {
		client, conn := net.Pipe()
		upstream, server := net.Pipe()
		done := make(chan error, 1)
		go func() {
			done <- Proxy(context.Background(), conn, func(context.Context) (net.Conn, error) {
				return upstream, nil
			}, "tnl_me", "app", func(string) error { return nil })
		}()
		forwarded := make(chan []byte, 1)
		go func() {
			b, _ := io.ReadAll(server)
			forwarded <- b
		}()

		login := startup("user", "tnl_me", "database", "app")
		go client.Write(slices.Concat(login, tt.msg))
		client.SetReadDeadline(time.Now().Add(10 * time.Second)) // a proxy that forwards the message waits for more
		reply, _ := io.ReadAll(client)
		client.Close()
		if err := <-done; !errors.As(err, new(*refusal)) {
			t.Errorf("%s: Proxy: %v, want a refusal", tt.name, err)
		}
		if len(reply) == 0 || reply[0] != 'E' || !bytes.Contains(reply, []byte("C"+tt.sqlstate+"\x00")) {
			t.Errorf("%s: client got %q, want an ErrorResponse with SQLSTATE %s", tt.name, reply, tt.sqlstate)
		}
		if got := <-forwarded; !bytes.Equal(got, login) {
			t.Errorf("%s: the server got %d bytes, want only the startup packet's %d", tt.name, len(got), len(login))
		}
	}
}

// TestRelayRefusesUnrecorded has the audit trail fail on the second
// statement. Neither that statement nor anything after it reaches the
// server: not even its message header.
func TestRelayRefusesUnrecorded(t *testing.T) {
	first, second := message('Q', "SELECT 1\x00"), message('Q', "DROP TABLE orders\x00")
	in := slices.Concat(first, second, message('Q', "SELECT 2\x00"))
	full := errors.New("no space left on device")
	var out bytes.Buffer
	statements := 0
	err := relay(&out, bytes.NewReader(in), func(string) error {
		if statements++; statements == 2 {
			return full
		}
		return nil
	})
	if !errors.Is(err, full) {
		t.Errorf("relay: %v, want the sink's error", err)
	}
	if !bytes.Equal(out.Bytes(), first) {
		t.Errorf("the server got %q, want only the recorded statement %q", out.Bytes(), first)
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
			}, "tnl_me", "app", func(string) error { return nil })
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

func TestRelayBackendStripsChannelBinding(t *testing.T) {
	sasl := func(mechs ...string) []byte {
		body := binary.BigEndian.AppendUint32(nil, authSASL)
		for _, m := range mechs {
			body = append(append(body, m...), 0)
		}
		return message('R', string(append(body, 0)))
	}
	ok := message('R', "\x00\x00\x00\x00")
	in := slices.Concat(
		sasl("SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"),
		message('R', "\x00\x00\x00\x0bserver-first\x00"), // AuthenticationSASLContinue, untouched
		ok,
		message('S', "server_version\x0017\x00"),
		message('R', "SCRAM-SHA-256-PLUS is just data now"), // after AuthenticationOk nothing is inspected
	)
	var out bytes.Buffer
	if err := relayBackend(&out, bytes.NewReader(in)); err != nil { // io.Copy ends cleanly at EOF
		t.Fatalf("relayBackend: %v", err)
	}
	want := slices.Concat(
		sasl("SCRAM-SHA-256"),
		message('R', "\x00\x00\x00\x0bserver-first\x00"),
		ok,
		message('S', "server_version\x0017\x00"),
		message('R', "SCRAM-SHA-256-PLUS is just data now"),
	)
	if !bytes.Equal(out.Bytes(), want) {
		t.Errorf("relayed\n%q\nwant\n%q", out.Bytes(), want)
	}
}
