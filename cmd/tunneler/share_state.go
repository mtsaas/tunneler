package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/publisher"
)

type shareLocalData struct {
	Server   string            `json:"server"`
	Request  api.ShareRequest  `json:"request"`
	Targets  map[string]string `json:"targets"`
	WorkerID string            `json:"worker_id"`
	Nonce    string            `json:"nonce"`
	Socket   string            `json:"socket"`
	Mode     string            `json:"mode"`
	State    string            `json:"state"`
	Share    *api.Share        `json:"share,omitempty"`
	Failure  string            `json:"failure,omitempty"`
}

type shareLocal struct {
	shareLocalData
	mu   sync.Mutex
	Path string
}

func (local *shareLocal) snapshot() *shareLocal {
	local.mu.Lock()
	defer local.mu.Unlock()
	return &shareLocal{shareLocalData: local.shareLocalData, Path: local.Path}
}

func shareStateDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tunneler", "shares"), nil
}

func shareStatePath(server, requestID string) (string, error) {
	dir, err := shareStateDir()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(server + "\x00" + requestID))
	return filepath.Join(dir, hex.EncodeToString(digest[:]), "state.json"), nil
}

func privateShareDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("share state directory must be private: %s", path)
	}
	return nil
}

func prepareShareLocal(server string, request api.ShareRequest, targets map[string]string, detached bool) (*shareLocal, bool, error) {
	path, err := shareStatePath(server, request.RequestID)
	if err != nil {
		return nil, false, err
	}
	if err := privateShareDir(filepath.Dir(filepath.Dir(path))); err != nil {
		return nil, false, err
	}
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		if !os.IsExist(err) {
			return nil, false, err
		}
		var local *shareLocal
		for attempt := 0; attempt < 20; attempt++ {
			local, err = readShareLocal(path)
			if err == nil {
				break
			}
			if !os.IsNotExist(err) {
				return nil, false, err
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil {
			return nil, false, errors.New("another start is preparing this request ID; inspect it before retrying")
		}
		if local.Request.ManifestDigest != request.ManifestDigest || local.Request.TTL != request.TTL || local.Request.Access != request.Access {
			return nil, false, shareError{error: errors.New("request ID was already used with different services or lifetime"), code: "idempotency_conflict", status: exitUsage, requestID: request.RequestID}
		}
		return local, true, nil
	}
	mode := "foreground"
	if detached {
		mode = "detached"
	}
	workerID := rand.Text()
	configDir, _ := os.UserConfigDir()
	digest := sha256.Sum256([]byte(configDir))
	ipcDir := filepath.Join(os.TempDir(), "ts-"+hex.EncodeToString(digest[:4]))
	if err := privateShareDir(ipcDir); err != nil {
		os.Remove(filepath.Dir(path))
		return nil, false, err
	}
	socketDigest := sha256.Sum256([]byte(workerID))
	socket := filepath.Join(ipcDir, hex.EncodeToString(socketDigest[:8]))
	if len(socket) > 100 {
		os.Remove(filepath.Dir(path))
		return nil, false, errors.New("temporary directory path is too long for private share IPC")
	}
	local := &shareLocal{shareLocalData: shareLocalData{Server: server, Request: request, Targets: targets, WorkerID: workerID, Nonce: rand.Text(), Socket: socket, Mode: mode, State: "starting"}, Path: path}
	if err := writeShareLocal(local); err != nil {
		os.RemoveAll(filepath.Dir(path))
		return nil, false, err
	}
	return local, false, nil
}

func writeShareLocal(local *shareLocal) error {
	local.mu.Lock()
	defer local.mu.Unlock()
	return writePrivateState(local.Path, local.shareLocalData)
}

func updateShareLocal(local *shareLocal, state string, s *api.Share, failure string) error {
	local.mu.Lock()
	defer local.mu.Unlock()
	if local.State == "ended" && (state != "" && state != "ended" || s != nil && s.State != "ended") {
		return errors.New("local share is already ended")
	}
	if state != "" {
		local.State = state
	}
	if s != nil {
		local.Share = s
	}
	if failure != "" {
		local.Failure = failure
	}
	return writePrivateState(local.Path, local.shareLocalData)
}

func readShareLocal(path string) (*shareLocal, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("share state file is not private")
	}
	local := &shareLocal{Path: path}
	if err := json.NewDecoder(io.LimitReader(f, 128<<10)).Decode(&local.shareLocalData); err != nil {
		return nil, err
	}
	return local, nil
}

func findShareLocal(server, id, requestID string) *shareLocal {
	if requestID != "" {
		path, err := shareStatePath(server, requestID)
		if err == nil {
			if local, err := readShareLocal(path); err == nil {
				return local
			}
		}
		return nil
	}
	dir, err := shareStateDir()
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		local, err := readShareLocal(filepath.Join(dir, entry.Name(), "state.json"))
		if err == nil && local.Server == server && local.Share != nil && local.Share.ID == id {
			return local
		}
	}
	return nil
}

type shareIPCRequest struct {
	Nonce     string `json:"nonce"`
	Operation string `json:"operation"`
}
type shareIPCReply struct {
	Local   *shareLocalData `json:"local,omitempty"`
	Stopped bool            `json:"local_stopped"`
	Error   string          `json:"error,omitempty"`
}

func startShareIPC(ctx context.Context, local *shareLocal, cancel context.CancelFunc, stopped <-chan struct{}) (net.Listener, error) {
	ln, err := net.Listen("unix", local.Socket)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(local.Socket, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	go func() { <-ctx.Done(); ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				var request shareIPCRequest
				if json.NewDecoder(io.LimitReader(conn, 8<<10)).Decode(&request) != nil {
					return
				}
				if subtle.ConstantTimeCompare([]byte(request.Nonce), []byte(local.Nonce)) != 1 {
					return
				}
				reply := shareIPCReply{}
				switch request.Operation {
				case "inspect":
				case "stop":
					cancel()
					select {
					case <-stopped:
						reply.Stopped = true
					case <-time.After(5 * time.Second):
						reply.Error = "local cleanup has not completed"
					}
				default:
					return
				}
				current := local.snapshot()
				reply.Local = &current.shareLocalData
				_ = json.NewEncoder(conn).Encode(reply)
			}()
		}
	}()
	return ln, nil
}

func shareIPC(ctx context.Context, local *shareLocal, operation string) (*shareIPCReply, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", local.Socket)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	if err := json.NewEncoder(conn).Encode(shareIPCRequest{local.Nonce, operation}); err != nil {
		return nil, err
	}
	var reply shareIPCReply
	if err := json.NewDecoder(io.LimitReader(conn, 128<<10)).Decode(&reply); err != nil {
		return nil, err
	}
	return &reply, nil
}

func stopShareLocal(ctx context.Context, local *shareLocal) bool {
	reply, err := shareIPC(ctx, local, "stop")
	return err == nil && reply.Stopped
}

type sharePublisherClient struct {
	*client
	local     *shareLocal
	ownership *atomic.Bool
}

func (c sharePublisherClient) PublisherAttached(s *api.Share) error {
	c.ownership.Store(s.Generation != "")
	return updateShareLocal(c.local, "", s, "")
}

func (c sharePublisherClient) RenewShare(ctx context.Context, id, generation string) (*api.Share, error) {
	s, err := c.client.RenewShare(ctx, id, generation)
	if err == nil {
		err = updateShareLocal(c.local, "", s, "")
	}
	return s, err
}

func runShareLocal(parent context.Context, c *client, local *shareLocal, ready func(context.Context, *api.Share) error) (err error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stopped := make(chan struct{})
	var stopOnce sync.Once
	ownership := new(atomic.Bool)
	localStopped := func() { stopOnce.Do(func() { close(stopped) }) }
	ln, err := startShareIPC(ctx, local, cancel, stopped)
	if err != nil {
		localStopped()
		_ = updateShareLocal(local, "ended", nil, err.Error())
		return err
	}
	defer ln.Close()
	timer := time.AfterFunc(time.Until(local.Request.StartupDeadline), func() {
		if local.snapshot().State != "ready" {
			cancel()
		}
	})
	defer timer.Stop()
	defer func() {
		localStopped()
		current := local.snapshot()
		var terminal *api.Share
		if current.Share != nil && ownership.Load() {
			cleanupCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
			terminal, _ = c.StopShare(cleanupCtx, current.Share.ID)
			stop()
		}
		failure := ""
		if err != nil {
			failure = err.Error()
		}
		_ = updateShareLocal(local, "ended", terminal, failure)
	}()
	s, err := c.CreateShare(ctx, local.Request)
	if err != nil {
		return err
	}
	if err := updateShareLocal(local, "starting", s, ""); err != nil {
		return err
	}
	if s.State == "ended" {
		return shareEnded(local, s)
	}
	if s.State == "ready" {
		return errors.New("this request already has an active publisher; inspect it instead")
	}
	err = publisher.Run(ctx, sharePublisherClient{c, local, ownership}, s, local.Targets, ready)
	cancel()
	localStopped()
	if parent.Err() != nil {
		return nil
	}
	if err != nil {
		inspectCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		terminal, inspectErr := c.Share(inspectCtx, s.ID)
		stop()
		if inspectErr == nil && terminal.State == "ended" {
			_ = updateShareLocal(local, "", terminal, "")
			if terminal.TerminalReason == "expired" || terminal.TerminalReason == "stopped" {
				return nil
			}
			return shareEnded(local, terminal)
		}
		return shareError{error: err, code: "publisher_unavailable", status: exitUnavailable, shareID: s.ID, requestID: local.Request.RequestID}
	}
	if parent.Err() == nil && local.snapshot().State != "ready" {
		return shareError{error: errors.New("share startup was cancelled before readiness"), code: "startup_timeout", status: exitUnavailable, shareID: s.ID, requestID: local.Request.RequestID}
	}
	return nil
}
