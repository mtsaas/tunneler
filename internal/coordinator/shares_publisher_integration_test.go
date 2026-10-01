package coordinator

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/publisher"
	"github.com/mtsaas/tunneler/internal/testutil"
)

func TestShareRealPublisherHTTPUpgradeAndRenewal(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/opaque" {
			io.WriteString(w, "web application")
			return
		}
		if r.Header.Get("Upgrade") != "development-echo" {
			http.Error(w, "wrong upgrade protocol", http.StatusBadRequest)
			return
		}
		conn, buffered, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: development-echo\r\n\r\n\x00\x04\xff\x00\x80\x7f")
		if err := buffered.Flush(); err != nil {
			return
		}
		io.Copy(conn, buffered.Reader)
	}))
	defer app.Close()
	apiApp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "api application")
	}))
	defer apiApp.Close()

	cfg := shareTestConfig(t)
	cfg.Sharing.AuthorizationLease = Duration(500 * time.Millisecond)
	cfg.Sharing.HeartbeatInterval = Duration(50 * time.Millisecond)
	cfg.Sharing.HeartbeatTimeout = Duration(300 * time.Millisecond)
	c := shareTestCoordinator(t, cfg)
	server := httptest.NewTLSServer(c.Handler())
	defer server.Close()
	client := shareTestClient(server.URL, "alice")
	client.HTTP = server.Client()
	request := shareTestRequest("real-publisher-path", "web", "api")
	request.TTL = "3s"
	share, err := client.CreateShare(context.Background(), request)
	testutil.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan *api.Share, 1)
	done := make(chan error, 1)
	go func() {
		done <- publisher.Run(ctx, client, share, map[string]string{
			"web": strings.TrimPrefix(app.URL, "http://"),
			"api": strings.TrimPrefix(apiApp.URL, "http://"),
		}, func(_ context.Context, share *api.Share) error {
			ready <- share
			return nil
		})
	}()
	select {
	case share = <-ready:
	case err := <-done:
		t.Fatalf("publisher ended before readiness: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("publisher never became ready")
	}
	var webHost string
	for _, service := range share.Services {
		public, err := url.Parse(service.URL)
		testutil.NoError(t, err)
		if service.Name == "web" {
			webHost = public.Host
		}
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/application", nil)
		req.Host = public.Host
		response, err := server.Client().Do(req)
		testutil.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		testutil.Require(t, err == nil && response.StatusCode == 200 && string(body) == service.Name+" application", "%s response = %d %q, %v", service.Name, response.StatusCode, body, err)
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", strings.TrimPrefix(server.URL, "https://"), server.Client().Transport.(*http.Transport).TLSClientConfig)
	testutil.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	const earlyClientBytes = "\x00\x0a\x00\x01\x02\x7f\x80\xfe\xffABC"
	fmt.Fprintf(conn, "GET /opaque HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: development-echo\r\n\r\n%s", webHost, earlyClientBytes)
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	testutil.Require(t, err == nil && response.StatusCode == 101 && response.Header.Get("Upgrade") == "development-echo" && strings.EqualFold(response.Header.Get("Connection"), "Upgrade"), "upgrade response = %+v, %v", response, err)
	want := "\x00\x04\xff\x00\x80\x7f" + earlyClientBytes
	actual := make([]byte, len(want))
	if _, err := io.ReadFull(reader, actual); err != nil || string(actual) != want {
		t.Fatalf("coalesced upgrade bytes = %q, %v", actual, err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		current, err := client.Share(context.Background(), share.ID)
		testutil.NoError(t, err)
		if current.AuthorizationDeadline.After(share.AuthorizationDeadline.Add(100 * time.Millisecond)) {
			break
		}
		testutil.Require(t, !time.Now().After(deadline), "real publisher did not renew its authorization lease")
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := client.StopShare(context.Background(), share.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("upgraded connection remained open after stop")
	}
	testutil.Receive(t, done, time.Second, "real publisher did not exit after remote stop")
}

func TestShareStopUnblocksIncompleteHTTPUpload(t *testing.T) {
	upstreamStarted := make(chan struct{})
	upstreamEnded := make(chan struct{})
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(upstreamStarted)
		defer close(upstreamEnded)
		io.Copy(io.Discard, r.Body)
	}))
	defer app.Close()
	c := shareTestCoordinator(t, shareTestConfig(t))
	frontendEnded := make(chan struct{})
	handler := c.Handler()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/upload" {
			defer close(frontendEnded)
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	client := shareTestClient(server.URL, "alice")
	share, err := client.CreateShare(context.Background(), shareTestRequest("incomplete-upload", "web"))
	testutil.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{}, 1)
	go publisher.Run(ctx, client, share, map[string]string{"web": strings.TrimPrefix(app.URL, "http://")}, func(context.Context, *api.Share) error {
		ready <- struct{}{}
		return nil
	})
	testutil.Receive(t, ready, 2*time.Second, "publisher never became ready")
	public, _ := url.Parse(share.Services[0].URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), time.Second)
	testutil.NoError(t, err)
	defer conn.Close()
	fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: %s\r\nContent-Length: 10\r\n\r\nx", public.Host)
	testutil.Receive(t, upstreamStarted, time.Second, "upload did not reach the local application")
	if _, err := client.StopShare(context.Background(), share.ID); err != nil {
		t.Fatal(err)
	}
	testutil.Receive(t, upstreamEnded, time.Second, "stop did not release the local upload handler")
	testutil.Receive(t, frontendEnded, time.Second, "stop left the frontend waiting for the incomplete request body")
}
