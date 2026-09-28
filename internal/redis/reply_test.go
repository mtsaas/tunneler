package redis

import (
	"net"
	"strings"
	"testing"

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
