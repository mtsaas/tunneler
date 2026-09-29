package redis

import (
	"bytes"
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

// Proxy requires Redis to authenticate the temporary user before forwarding
// other commands. It then audits complete commands and forwards their original
// wire bytes. Cluster replies are translated to local node ports.
func Proxy(ctx context.Context, local net.Conn, dial func(context.Context) (net.Conn, error), options ProxyOptions) error {
	defer local.Close()
	upstream, err := dial(ctx)
	if err != nil {
		writeProxyError(local, "cannot reach Redis")
		return err
	}
	defer upstream.Close()
	reader := newCommandReader(local)
	initialCommand, firstReplyByte, err := authenticate(upstream, reader, options)
	if err != nil {
		writeProxyError(local, err.Error())
		return err
	}

	if options.Mode == ModeCluster {
		return proxyCluster(local, upstream, reader, initialCommand, firstReplyByte, options)
	}
	return proxySingle(local, upstream, reader, firstReplyByte, options)
}

func proxySingle(local, upstream net.Conn, reader *commandReader, firstReplyByte byte, options ProxyOptions) error {
	results := make(chan error, 2)
	go func() {
		proxyWorker(results, func() error {
			_, err := io.Copy(local, io.MultiReader(bytes.NewReader([]byte{firstReplyByte}), upstream))
			return err
		})
	}()
	go func() {
		proxyWorker(results, func() error {
			return forwardCommands(reader, upstream, options, nil, nil)
		})
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

func proxyCluster(local, upstream net.Conn, reader *commandReader,
	initialCommand string, firstReplyByte byte, options ProxyOptions) error {
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
	requests <- initialCommand
	results := make(chan error, 2)
	done := make(chan struct{})
	go func() {
		defer close(requests)
		proxyWorker(results, func() error {
			return forwardCommands(reader, upstream, options, requests, done)
		})
	}()
	go func() {
		proxyWorker(results, func() error {
			reader := newReplyReader(upstream)
			reader.pending = []byte{firstReplyByte}
			for command := range requests {
				reply, err := reader.Next(maxReplyBytes)
				if err != nil {
					return err
				}
				translated, err := translateReply(command, reply, ports, redirects)
				if err == nil {
					_, err = local.Write(translated)
				}
				if err != nil {
					return err
				}
			}
			return io.EOF
		})
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

// Keep a parser panic inside its connection. The proxy closes both sides and
// returns the error to its caller, which logs the closed connection.
func proxyWorker(results chan<- error, work func() error) {
	defer func() {
		if recover() != nil {
			results <- errors.New("redis: proxy connection panicked")
		}
	}()
	results <- work()
}

func isClosed(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

func writeProxyError(conn net.Conn, message string) {
	_, _ = conn.Write(redcon.AppendError(nil, "ERR tunneler: "+message))
}

// authenticate leaves Redis to check the password, but does not let a client
// use the connection as Redis's default user before that check succeeds.
func authenticate(upstream net.Conn, reader *commandReader, options ProxyOptions) (string, byte, error) {
	command, err := reader.ReadCommand()
	if err != nil {
		return "", 0, err
	}
	name := strings.ToUpper(string(command.Args[0]))
	if name != "AUTH" && (name != "HELLO" || !helloAuthenticates(command.Args)) {
		return "", 0, errors.New("redis: authenticate as the temporary user before sending other commands")
	}
	if err := checkCommand(name, command.Args, options); err != nil {
		return "", 0, err
	}
	if err := options.Audit(name, auditArguments(name, command.Args)); err != nil {
		return "", 0, fmt.Errorf("redis: audit failed: %w", err)
	}
	if _, err := upstream.Write(command.Raw); err != nil {
		return "", 0, err
	}
	var first [1]byte
	if _, err := io.ReadFull(upstream, first[:]); err != nil {
		return "", 0, err
	}
	if first[0] == '-' {
		return "", 0, errors.New("redis: temporary user authentication failed")
	}
	if name == "AUTH" && first[0] != '+' || name == "HELLO" && first[0] != '*' && first[0] != '%' {
		return "", 0, errors.New("redis: invalid authentication reply")
	}
	return name, first[0], nil
}

func helloAuthenticates(args [][]byte) bool {
	for _, arg := range args[1:] {
		if strings.EqualFold(string(arg), "AUTH") {
			return true
		}
	}
	return false
}

// forwardCommands uses the same reader as authenticate, retaining any client
// commands that arrived in the same packet as the authentication handshake.
func forwardCommands(reader *commandReader, upstream net.Conn,
	options ProxyOptions, requests chan<- string, done <-chan struct{}) error {
	for {
		command, err := reader.ReadCommand()
		if err != nil {
			return err
		}
		name := strings.ToUpper(string(command.Args[0]))
		if err := checkCommand(name, command.Args, options); err != nil {
			return err
		}
		if name == "AUTH" || name == "HELLO" && helloAuthenticates(command.Args) {
			return errors.New("redis: this connection is already authenticated as its temporary user")
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
	case "CLIENT":
		if len(args) > 1 && (strings.EqualFold(string(args[1]), "SETINFO") || strings.EqualFold(string(args[1]), "SETNAME")) {
			return nil
		}
		return errors.New("redis: this session does not permit server control commands")
	case "FAILOVER":
		return errors.New("redis: this session does not permit server control commands")
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
