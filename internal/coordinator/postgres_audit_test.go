package coordinator

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"golang.org/x/text/encoding/japanese"
)

func pgMessage(typ byte, body []byte) []byte {
	return append(binary.BigEndian.AppendUint32([]byte{typ}, uint32(len(body)+4)), body...)
}

func readPGMessage(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	body := make([]byte, binary.BigEndian.Uint32(hdr[1:])-4)
	_, err := io.ReadFull(r, body)
	return hdr[0], body, err
}

// replayEncoding uses the two wire-ordered audit streams as a reviewer would:
// each frontend command is matched to its backend completion, with status
// changes applied in the backend's order before the next SQL is parsed.
func replayEncoding(t *testing.T, records []map[string]any) map[float64]string {
	t.Helper()
	var frontend, backend []map[string]any
	for _, record := range records {
		switch record["msg"] {
		case "query", "postgres frontend":
			frontend = append(frontend, record)
		case "postgres backend":
			backend = append(backend, record)
		}
	}
	sort.Slice(frontend, func(i, j int) bool {
		return frontend[i]["frontend_seq"].(float64) < frontend[j]["frontend_seq"].(float64)
	})
	sort.Slice(backend, func(i, j int) bool { return backend[i]["backend_seq"].(float64) < backend[j]["backend_seq"].(float64) })
	var encoding string
	bi := 0
	consume := func(complete string) {
		for bi < len(backend) {
			event := backend[bi]
			bi++
			if event["backend_type"] == "S" && event["parameter_name"] == "client_encoding" {
				encoding = event["parameter_value"].(string)
			}
			if strings.Contains(complete, event["backend_type"].(string)) {
				return
			}
		}
		t.Fatalf("backend audit ended before completion %q: %#v", complete, backend)
	}
	consume("Z") // startup, including the backend's initial client_encoding
	result := make(map[float64]string)
	for _, event := range frontend {
		typ := event["frontend_type"].(string)
		if typ == "Q" && event["msg"] == "query" {
			result[event["frontend_seq"].(float64)] = encoding
		}
		switch typ {
		case "Q", "S":
			consume("Z")
		case "P":
			consume("1E")
			if event["msg"] == "query" {
				result[event["frontend_seq"].(float64)] = encoding
			}
		case "B":
			consume("2E")
		case "E":
			consume("CsIE")
		case "D":
			consume("TnE")
		case "C":
			consume("3E")
		case "H":
		default:
			t.Fatalf("frontend audit did not identify the protocol message: %#v", event)
		}
	}
	return result
}

func requireDecodedSJIS(t *testing.T, query map[string]any) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(query["sql_bytes_base64"].(string))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := japanese.ShiftJIS.NewDecoder().Bytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(decoded); got != "SELECT '―';" {
		t.Fatalf("decoded SQL = %q, want the SJIS character in one string literal", got)
	}
}

func TestPostgresAuditPreservesPipelinedEncodingChanges(t *testing.T) {
	var audit bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&audit, nil))
	client, proxyClient := net.Pipe()
	proxyServer, server := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	client.SetDeadline(deadline)
	server.SetDeadline(deadline)
	ctx := context.Background()
	done := make(chan error, 1)
	go func() {
		done <- kinds["postgres"].proxy(ctx, proxyClient, func(context.Context) (net.Conn, error) {
			return proxyServer, nil
		}, &api.Session{Username: "tnl_me", Database: "app"}, proxyConnection{}, logger)
	}()
	serverDone := make(chan error, 1)
	go func() {
		var hdr [4]byte
		if _, err := io.ReadFull(server, hdr[:]); err != nil {
			serverDone <- err
			return
		}
		body := make([]byte, binary.BigEndian.Uint32(hdr[:])-4)
		if _, err := io.ReadFull(server, body); err != nil {
			serverDone <- err
			return
		}
		for _, msg := range [][]byte{
			pgMessage('R', []byte{0, 0, 0, 0}),
			pgMessage('S', []byte("client_encoding\x00UTF8\x00")),
			pgMessage('Z', []byte{'I'}),
		} {
			if _, err := server.Write(msg); err != nil {
				serverDone <- err
				return
			}
		}
		for i := 0; i < 2; i++ {
			if typ, _, err := readPGMessage(server); err != nil || typ != 'Q' {
				serverDone <- err
				return
			}
		}
		for _, msg := range [][]byte{
			pgMessage('C', []byte("SET\x00")),
			pgMessage('S', []byte("client_encoding\x00SJIS\x00")),
			pgMessage('Z', []byte{'I'}),
			pgMessage('C', []byte("SELECT 1\x00")),
			pgMessage('Z', []byte{'I'}),
		} {
			if _, err := server.Write(msg); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()
	startup := binary.BigEndian.AppendUint32(nil, 3<<16)
	for _, v := range []string{"user", "tnl_me", "database", "app", "client_encoding", "UTF8", "options", "-c search_path=private"} {
		startup = append(append(startup, v...), 0)
	}
	startup = append(startup, 0)
	if _, err := client.Write(binary.BigEndian.AppendUint32(nil, uint32(len(startup)+4))); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(startup); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, _, err := readPGMessage(client); err != nil {
			t.Fatal(err)
		}
	}
	sjis := []byte{'S', 'E', 'L', 'E', 'C', 'T', ' ', '\'', 0x81, 0x5c, '\'', ';', 0}
	queries := append(pgMessage('Q', []byte("SET client_encoding TO SJIS\x00")), pgMessage('Q', sjis)...)
	if _, err := client.Write(queries); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, _, err := readPGMessage(client); err != nil {
			t.Fatal(err)
		}
	}
	client.Close()
	server.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	<-done

	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(audit.String()), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	var startupRecord, changed, firstQuery, secondQuery map[string]any
	for _, record := range records {
		switch record["msg"] {
		case "postgres startup":
			startupRecord = record
		case "postgres backend":
			if record["parameter_name"] == "client_encoding" && record["parameter_value"] == "SJIS" {
				changed = record
			}
		case "query":
			if record["sql"] == "SET client_encoding TO SJIS" {
				firstQuery = record
			}
			if record["sql_bytes_base64"] == base64.StdEncoding.EncodeToString(sjis[:len(sjis)-1]) {
				secondQuery = record
			}
		}
	}
	if startupRecord == nil || changed == nil || firstQuery == nil || secondQuery == nil {
		t.Fatalf("audit does not preserve startup context, encoding change, and raw query bytes: %#v", records)
	}
	if startupRecord["startup_parameters"].(map[string]any)["options"] != "-c search_path=private" {
		t.Fatalf("startup options absent: %#v", startupRecord)
	}
	if got := replayEncoding(t, records)[secondQuery["frontend_seq"].(float64)]; got != "SJIS" {
		t.Fatalf("pipelined query's server encoding = %q, want SJIS: %#v", got, records)
	}
	requireDecodedSJIS(t, secondQuery)
	if secondQuery["sql"] != nil {
		t.Fatalf("ambiguous SQL text was presented as authoritative: %#v", secondQuery)
	}
}

func TestPostgresAuditPreservesExtendedPipelineEncoding(t *testing.T) {
	var audit bytes.Buffer
	client, proxyClient := net.Pipe()
	proxyServer, server := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	client.SetDeadline(deadline)
	server.SetDeadline(deadline)
	done := make(chan error, 1)
	go func() {
		done <- kinds["postgres"].proxy(context.Background(), proxyClient, func(context.Context) (net.Conn, error) {
			return proxyServer, nil
		}, &api.Session{Username: "tnl_me", Database: "app"}, proxyConnection{}, slog.New(slog.NewJSONHandler(&audit, nil)))
	}()
	serverDone := make(chan error, 1)
	go func() {
		var hdr [4]byte
		if _, err := io.ReadFull(server, hdr[:]); err != nil {
			serverDone <- err
			return
		}
		if _, err := io.CopyN(io.Discard, server, int64(binary.BigEndian.Uint32(hdr[:])-4)); err != nil {
			serverDone <- err
			return
		}
		for _, msg := range [][]byte{
			pgMessage('R', []byte{0, 0, 0, 0}),
			pgMessage('S', []byte("client_encoding\x00UTF8\x00")),
			pgMessage('Z', []byte{'I'}),
		} {
			if _, err := server.Write(msg); err != nil {
				serverDone <- err
				return
			}
		}
		for _, want := range "PBEPBES" {
			typ, _, err := readPGMessage(server)
			if err != nil {
				serverDone <- err
				return
			}
			if typ != byte(want) {
				serverDone <- io.ErrUnexpectedEOF
				return
			}
		}
		for _, msg := range [][]byte{
			pgMessage('1', nil),
			pgMessage('2', nil),
			pgMessage('C', []byte("SET\x00")),
			pgMessage('S', []byte("client_encoding\x00SJIS\x00")),
			pgMessage('1', nil),
			pgMessage('2', nil),
			pgMessage('C', []byte("SELECT 1\x00")),
			pgMessage('Z', []byte{'I'}),
		} {
			if _, err := server.Write(msg); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()
	startup := binary.BigEndian.AppendUint32(nil, 3<<16)
	for _, v := range []string{"user", "tnl_me", "database", "app"} {
		startup = append(append(startup, v...), 0)
	}
	startup = append(startup, 0)
	if _, err := client.Write(binary.BigEndian.AppendUint32(nil, uint32(len(startup)+4))); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(startup); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, _, err := readPGMessage(client); err != nil {
			t.Fatal(err)
		}
	}
	parse := func(name string, sql []byte) []byte {
		body := append(append(append([]byte(name), 0), sql...), 0, 0, 0)
		return pgMessage('P', body)
	}
	bind := func(name string) []byte {
		body := append([]byte{0}, name...)
		return pgMessage('B', append(body, 0, 0, 0, 0, 0, 0, 0))
	}
	sjis := []byte{'S', 'E', 'L', 'E', 'C', 'T', ' ', '\'', 0x81, 0x5c, '\'', ';'}
	frontend := bytes.Join([][]byte{
		parse("p1", []byte("SET client_encoding TO SJIS")), bind("p1"), pgMessage('E', []byte{0, 0, 0, 0, 0}),
		parse("p2", sjis), bind("p2"), pgMessage('E', []byte{0, 0, 0, 0, 0}), pgMessage('S', nil),
	}, nil)
	if _, err := client.Write(frontend); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, _, err := readPGMessage(client); err != nil {
			t.Fatal(err)
		}
	}
	client.Close()
	server.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	<-done
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(audit.String()), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	var secondQuery map[string]any
	for _, record := range records {
		if record["msg"] == "query" && record["sql_bytes_base64"] == base64.StdEncoding.EncodeToString(sjis) {
			secondQuery = record
		}
	}
	if secondQuery == nil {
		t.Fatalf("extended Parse bytes absent: %#v", records)
	}
	if got := replayEncoding(t, records)[secondQuery["frontend_seq"].(float64)]; got != "SJIS" {
		t.Fatalf("extended pipeline's second Parse encoding = %q, want SJIS: %#v", got, records)
	}
	requireDecodedSJIS(t, secondQuery)
}
