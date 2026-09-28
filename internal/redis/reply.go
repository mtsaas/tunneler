package redis

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/tidwall/redcon"
)

type byteBudget struct {
	io.Reader
	Limit int
	used  int
}

func (b *byteBudget) Reset() { b.used = 0 }

func (b *byteBudget) Read(p []byte) (int, error) {
	remaining := b.Limit - b.used
	if remaining <= 0 {
		return 0, errors.New("redis: command exceeds the read limit")
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	n, err := b.Reader.Read(p)
	b.used += n
	return n, err
}

// replyReader uses redcon's RESP2 parser. A Cluster session explicitly
// rejects HELLO 3, so all replies use this format. Non-Cluster sessions
// splice replies without parsing them and can use RESP3.
type replyReader struct {
	conn    net.Conn
	pending []byte
}

func newReplyReader(conn net.Conn) *replyReader { return &replyReader{conn: conn} }

func (r *replyReader) Next(limit int) (redcon.RESP, error) {
	for {
		n, reply := redcon.ReadNextRESP(r.pending)
		if n > 0 {
			r.pending = r.pending[n:]
			return reply, nil
		}
		if len(r.pending) >= limit {
			return redcon.RESP{}, errors.New("redis: Cluster reply exceeds 64 MiB")
		}
		var buf [32 << 10]byte
		n, err := r.conn.Read(buf[:min(len(buf), limit-len(r.pending))])
		r.pending = append(r.pending, buf[:n]...)
		if err != nil {
			return redcon.RESP{}, err
		}
	}
}

func translateReply(command string, reply redcon.RESP, ports map[string]int, redirects map[string]string) ([]byte, error) {
	if reply.Type == redcon.Error {
		parts := strings.Fields(reply.String())
		if len(parts) == 3 && (parts[0] == "MOVED" || parts[0] == "ASK") {
			addr, found := redirects[parts[2]]
			if !found {
				return nil, errors.New("redis: redirect names an unadvertised node")
			}
			return redcon.AppendError(nil, parts[0]+" "+parts[1]+" "+addr), nil
		}
	}
	switch command {
	case "CLUSTER SHARDS":
		return translateShards(reply, ports)
	case "CLUSTER SLOTS":
		return translateSlots(reply, ports)
	default:
		return reply.Raw, nil
	}
}

func respItems(reply redcon.RESP) []redcon.RESP {
	var items []redcon.RESP
	reply.ForEach(func(item redcon.RESP) bool {
		items = append(items, item)
		return true
	})
	return items
}

func translateShards(reply redcon.RESP, ports map[string]int) ([]byte, error) {
	if reply.Type != redcon.Array {
		return reply.Raw, nil
	}
	shards := respItems(reply)
	result := redcon.AppendArray(nil, len(shards))
	for _, shard := range shards {
		fields := respItems(shard)
		if len(fields)%2 != 0 {
			return nil, errors.New("redis: invalid CLUSTER SHARDS reply")
		}
		result = redcon.AppendArray(result, len(fields))
		for i := 0; i < len(fields); i += 2 {
			result = append(result, fields[i].Raw...)
			if fields[i].String() != "nodes" {
				result = append(result, fields[i+1].Raw...)
				continue
			}
			nodes := respItems(fields[i+1])
			result = redcon.AppendArray(result, len(nodes))
			for _, node := range nodes {
				id := node.MapGet("id").String()
				port := ports[id]
				if port == 0 {
					return nil, errors.New("redis: CLUSTER SHARDS contains an unadvertised node")
				}
				result = appendVirtualNode(result, node, port)
			}
		}
	}
	return result, nil
}

func appendVirtualNode(result []byte, node redcon.RESP, port int) []byte {
	fields := respItems(node)
	result = redcon.AppendArray(result, len(fields))
	for i := 0; i < len(fields); i += 2 {
		result = append(result, fields[i].Raw...)
		switch fields[i].String() {
		case "endpoint", "ip", "hostname":
			result = redcon.AppendBulkString(result, "127.0.0.1")
		case "port", "tls-port":
			result = redcon.AppendInt(result, int64(port))
		default:
			result = append(result, fields[i+1].Raw...)
		}
	}
	return result
}

func translateSlots(reply redcon.RESP, ports map[string]int) ([]byte, error) {
	if reply.Type != redcon.Array {
		return reply.Raw, nil
	}
	slots := respItems(reply)
	result := redcon.AppendArray(nil, len(slots))
	for _, slot := range slots {
		fields := respItems(slot)
		if len(fields) < 3 {
			return nil, errors.New("redis: invalid CLUSTER SLOTS reply")
		}
		result = redcon.AppendArray(result, len(fields))
		result = append(result, fields[0].Raw...)
		result = append(result, fields[1].Raw...)
		for _, node := range fields[2:] {
			parts := respItems(node)
			if len(parts) < 3 {
				return nil, errors.New("redis: incomplete CLUSTER SLOTS node")
			}
			port := ports[parts[2].String()]
			if port == 0 {
				return nil, errors.New("redis: CLUSTER SLOTS contains an unadvertised node")
			}
			result = redcon.AppendArray(result, len(parts))
			result = redcon.AppendBulkString(result, "127.0.0.1")
			result = redcon.AppendInt(result, int64(port))
			for _, extra := range parts[2:] {
				result = append(result, extra.Raw...)
			}
		}
	}
	return result, nil
}

func virtualAddress(port int) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

func validatePorts(nodes []Node, ports map[string]int) error {
	for _, node := range nodes {
		port := ports[node.ID]
		if port < 1 || port > 65535 {
			return fmt.Errorf("redis: missing local port for node %s", node.ID)
		}
	}
	return nil
}
