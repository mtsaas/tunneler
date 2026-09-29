package redis

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tidwall/redcon"
)

func readPipeReply(t *testing.T, wire string) (redcon.RESP, error) {
	t.Helper()
	reader, writer := net.Pipe()
	defer reader.Close()
	go func() {
		_, _ = writer.Write([]byte(wire))
		writer.Close()
	}()
	return newReplyReader(reader).Next(maxReplyBytes)
}

func TestReplyReaderRejectsOverflowingBulkLength(t *testing.T) {
	_, err := readPipeReply(t, "$9223372036854775807\r\n")
	if err == nil || !strings.Contains(err.Error(), "bulk length") {
		t.Fatalf("Next() error = %v, want invalid bulk length", err)
	}
}

func TestReplyReaderRejectsDeepArrays(t *testing.T) {
	_, err := readPipeReply(t, strings.Repeat("*1\r\n", 65)+"+ok\r\n")
	if err == nil || !strings.Contains(err.Error(), "nesting depth") {
		t.Fatalf("Next() error = %v, want nesting depth error", err)
	}
}

func TestReplyReaderKeepsPipelinedReplies(t *testing.T) {
	reader, writer := net.Pipe()
	defer reader.Close()
	go func() {
		_, _ = writer.Write([]byte("*2\r\n$3\r\none\r\n$3\r\ntwo\r\n+next\r\n"))
		writer.Close()
	}()
	r := newReplyReader(reader)
	first, err := r.Next(maxReplyBytes)
	if err != nil || first.Type != redcon.Array || len(respItems(first)) != 2 {
		t.Fatalf("first reply = %q, %v", first.Raw, err)
	}
	second, err := r.Next(maxReplyBytes)
	if err != nil || string(second.Raw) != "+next\r\n" {
		t.Fatalf("second reply = %q, %v", second.Raw, err)
	}
}

func TestReplyReaderHandlesSplitHeadersAndBulk(t *testing.T) {
	reader, writer := net.Pipe()
	defer reader.Close()
	go func() {
		for _, b := range []byte("*2\r\n$3\r\none\r\n*1\r\n+two\r\n") {
			if _, err := writer.Write([]byte{b}); err != nil {
				break
			}
		}
		writer.Close()
	}()
	reply, err := newReplyReader(reader).Next(maxReplyBytes)
	if err != nil || len(respItems(reply)) != 2 || string(reply.Raw) != "*2\r\n$3\r\none\r\n*1\r\n+two\r\n" {
		t.Fatalf("reply = %q, %v", reply.Raw, err)
	}
}

func TestTranslateShardsRejectsOddNodeFields(t *testing.T) {
	for _, finalKey := range []string{"role", "port"} {
		t.Run(finalKey, func(t *testing.T) {
			wire := redcon.AppendArray(nil, 1) // one shard
			wire = redcon.AppendArray(wire, 2)
			wire = redcon.AppendBulkString(wire, "nodes")
			wire = redcon.AppendArray(wire, 1) // one node
			wire = redcon.AppendArray(wire, 3) // odd number of node fields
			wire = redcon.AppendBulkString(wire, "id")
			wire = redcon.AppendBulkString(wire, "node-1")
			wire = redcon.AppendBulkString(wire, finalKey)

			reply, err := readPipeReply(t, string(wire))
			if err != nil {
				t.Fatal(err)
			}
			_, err = translateReply("CLUSTER SHARDS", reply, map[string]int{"node-1": 6379}, nil)
			if err == nil || !strings.Contains(err.Error(), "invalid CLUSTER SHARDS reply") {
				t.Fatalf("translateReply() error = %v, want invalid CLUSTER SHARDS reply", err)
			}
		})
	}
}

func TestProxyContainsWorkerPanic(t *testing.T) {
	client, local := net.Pipe()
	upstream, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	serverDone := make(chan error, 1)
	go func() {
		_, err := redcon.NewReader(server).ReadCommand()
		if err == nil {
			_, err = server.Write([]byte("+OK\r\n"))
		}
		serverDone <- err
	}()
	proxyDone := make(chan error, 1)
	go func() {
		proxyDone <- Proxy(context.Background(), local, func(context.Context) (net.Conn, error) {
			return upstream, nil
		}, ProxyOptions{
			Username: "temporary",
			Mode:     ModeStandalone,
			Audit: func(command string, _ []string) error {
				if command == "PING" {
					panic("unexpected worker failure")
				}
				return nil
			},
		})
	}()

	if _, err := client.Write(respCommand("AUTH", "temporary", "secret")); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	if reply, err := reader.ReadString('\n'); err != nil || reply != "+OK\r\n" {
		t.Fatalf("authentication reply = %q, %v", reply, err)
	}
	if _, err := client.Write(respCommand("PING")); err != nil {
		t.Fatal(err)
	}
	if reply, err := reader.ReadString('\n'); err != nil || !strings.Contains(reply, "proxy connection panicked") {
		t.Fatalf("panic reply = %q, %v", reply, err)
	}
	if err := <-proxyDone; err == nil || !strings.Contains(err.Error(), "proxy connection panicked") {
		t.Fatalf("Proxy() error = %v, want contained worker panic", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestProxyRejectsOverflowingCommandLength(t *testing.T) {
	client, local := net.Pipe()
	upstream, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	server.SetDeadline(time.Now().Add(5 * time.Second))

	serverDone := make(chan error, 1)
	go func() {
		reader := redcon.NewReader(server)
		_, err := reader.ReadCommand()
		if err == nil {
			_, err = server.Write([]byte("+OK\r\n"))
		}
		if err == nil {
			var next [1]byte
			_, err = server.Read(next[:])
		}
		serverDone <- err
	}()
	proxyDone := make(chan error, 1)
	go func() {
		proxyDone <- Proxy(context.Background(), local, func(context.Context) (net.Conn, error) {
			return upstream, nil
		}, ProxyOptions{
			Username: "temporary",
			Mode:     ModeStandalone,
			Audit:    func(string, []string) error { return nil },
		})
	}()

	if _, err := client.Write(respCommand("AUTH", "temporary", "secret")); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	if reply, err := reader.ReadString('\n'); err != nil || reply != "+OK\r\n" {
		t.Fatalf("authentication reply = %q, %v", reply, err)
	}
	if _, err := client.Write([]byte("*1\r\n$9223372036854775807\r\n")); err != nil {
		t.Fatal(err)
	}
	if reply, err := reader.ReadString('\n'); err != nil || !strings.Contains(reply, "invalid bulk length") {
		t.Fatalf("command reply = %q, %v, want invalid bulk length", reply, err)
	}
	if err := <-proxyDone; err == nil || !strings.Contains(err.Error(), "invalid bulk length") {
		t.Fatalf("Proxy() error = %v, want invalid bulk length", err)
	}
	if err := <-serverDone; err == nil {
		t.Fatal("invalid command reached Redis")
	}
}
