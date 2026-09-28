package redis

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tidwall/redcon"
)

const (
	maxCommandBytes = 1 << 20
	maxReplyBytes   = 64 << 20
)

type ProxyOptions struct {
	Username string
	Mode     string
	Nodes    []Node
	Ports    map[string]int // node ID to the CLI's local port
	Audit    func(command string, arguments []string) error
}

// Proxy keeps the client's authentication end to end with Redis. It inspects
// complete commands for session restrictions and audit, then forwards the
// original wire bytes. Cluster replies are translated to local node ports.
func Proxy(ctx context.Context, local net.Conn, dial func(context.Context) (net.Conn, error), options ProxyOptions) error {
	defer local.Close()
	upstream, err := dial(ctx)
	if err != nil {
		writeProxyError(local, "cannot reach Redis")
		return err
	}
	defer upstream.Close()

	if options.Mode == ModeCluster {
		return proxyCluster(local, upstream, options)
	}
	return proxySingle(local, upstream, options)
}

func proxySingle(local, upstream net.Conn, options ProxyOptions) error {
	results := make(chan error, 2)
	go func() {
		_, err := io.Copy(local, upstream)
		results <- err
	}()
	go func() {
		results <- forwardCommands(local, upstream, options, nil, nil)
	}()
	err := <-results
	upstream.Close()
	local.SetReadDeadline(time.Now())
	<-results
	if err != nil && !isClosed(err) {
		writeProxyError(local, err.Error())
	}
	if isClosed(err) {
		return nil
	}
	return err
}

func proxyCluster(local, upstream net.Conn, options ProxyOptions) error {
	redirects := make(map[string]string)
	ports := make(map[string]int)
	for _, node := range options.Nodes {
		port := options.Ports[node.ID]
		if port == 0 {
			return errors.New("redis: no local listener for an advertised cluster node")
		}
		ports[node.ID] = port
		redirects[node.Addr] = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	}

	requests := make(chan string, 32)
	results := make(chan error, 2)
	done := make(chan struct{})
	go func() {
		defer close(requests)
		results <- forwardCommands(local, upstream, options, requests, done)
	}()
	go func() {
		reader := newReplyReader(upstream)
		for command := range requests {
			reply, err := reader.Next(maxReplyBytes)
			if err != nil {
				results <- err
				return
			}
			translated, err := translateReply(command, reply, ports, redirects)
			if err == nil {
				_, err = local.Write(translated)
			}
			if err != nil {
				results <- err
				return
			}
		}
		results <- io.EOF
	}()

	err := <-results
	close(done)
	upstream.Close()
	local.SetReadDeadline(time.Now())
	<-results
	if err != nil && !isClosed(err) {
		writeProxyError(local, err.Error())
	}
	if isClosed(err) {
		return nil
	}
	return err
}

func isClosed(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

func writeProxyError(conn net.Conn, message string) {
	_, _ = conn.Write(redcon.AppendError(nil, "ERR tunneler: "+message))
}

// forwardCommands uses redcon's command reader; byteBudget prevents its
// internal buffer from growing without bound on a malformed client frame.
func forwardCommands(local, upstream net.Conn, options ProxyOptions, requests chan<- string, done <-chan struct{}) error {
	budget := &byteBudget{Reader: local, Limit: 2 * maxCommandBytes}
	reader := redcon.NewReader(budget)
	for {
		budget.Reset()
		command, err := reader.ReadCommand()
		if err != nil {
			return err
		}
		if len(command.Raw) > maxCommandBytes || len(command.Args) == 0 || len(command.Args) > 1024 || command.Raw[0] != '*' {
			return errors.New("redis: command must be a RESP array of at most 1 MiB and 1,024 arguments")
		}
		name := strings.ToUpper(string(command.Args[0]))
		if err := checkCommand(name, command.Args, options); err != nil {
			return err
		}
		if err := options.Audit(name, auditArguments(name, command.Args)); err != nil {
			return fmt.Errorf("redis: audit failed: %w", err)
		}
		if _, err := upstream.Write(command.Raw); err != nil {
			return err
		}
		if requests != nil {
			select {
			case requests <- topologyCommand(name, command.Args):
			case <-done:
				return net.ErrClosed
			}
		}
	}
}

func topologyCommand(name string, args [][]byte) string {
	if name == "CLUSTER" && len(args) > 1 {
		return "CLUSTER " + strings.ToUpper(string(args[1]))
	}
	return name
}

func checkCommand(name string, args [][]byte, options ProxyOptions) error {
	switch name {
	case "AUTH":
		if len(args) != 3 || string(args[1]) != options.Username {
			return errors.New("redis: this session permits AUTH only as its temporary user")
		}
	case "HELLO":
		if options.Mode == ModeCluster && len(args) > 1 && string(args[1]) == "3" {
			return errors.New("redis: Cluster sessions currently require RESP2")
		}
		for i := 1; i < len(args); i++ {
			if !strings.EqualFold(string(args[i]), "AUTH") {
				continue
			}
			if i+2 >= len(args) || string(args[i+1]) != options.Username {
				return errors.New("redis: this session permits HELLO AUTH only as its temporary user")
			}
			i += 2
		}
	case "CLUSTER":
		if options.Mode != ModeCluster || len(args) != 2 ||
			(!strings.EqualFold(string(args[1]), "SHARDS") && !strings.EqualFold(string(args[1]), "SLOTS")) {
			return errors.New("redis: only CLUSTER SHARDS and CLUSTER SLOTS are available")
		}
	case "SUBSCRIBE", "PSUBSCRIBE", "SSUBSCRIBE":
		if options.Mode == ModeCluster {
			return errors.New("redis: subscriptions are not supported in Cluster sessions")
		}
	}
	return nil
}

func auditArguments(name string, args [][]byte) []string {
	result := make([]string, len(args)-1)
	for i, arg := range args[1:] {
		password := name == "AUTH" && i == len(result)-1
		password = password || name == "HELLO" && i >= 2 && strings.EqualFold(string(args[i-1]), "AUTH")
		if password {
			result[i] = "<redacted>"
			continue
		}
		if utf8.Valid(arg) && !strings.ContainsAny(string(arg), "\x00\r\n") {
			result[i] = string(arg)
		} else {
			result[i] = "base64:" + base64.StdEncoding.EncodeToString(arg)
		}
	}
	return result
}
