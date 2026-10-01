package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/spf13/cobra"
)

type shareWorkerConfig struct {
	Local shareLocalData `json:"local"`
	Path  string         `json:"path"`
}
type shareWorkerMessage struct {
	Type    string       `json:"type"`
	Output  *shareOutput `json:"output,omitempty"`
	Error   string       `json:"error,omitempty"`
	Code    string       `json:"code,omitempty"`
	Status  int          `json:"status,omitempty"`
	ShareID string       `json:"share_id,omitempty"`
}
type shareWorkerAck struct {
	Type string `json:"type"`
}

var shareWorkerCommand = func(executable string) *exec.Cmd {
	return exec.Command(executable, "share", "_worker", "--output", "json")
}

func shareWorkerCmd() *cobra.Command {
	return &cobra.Command{Use: "_worker", Short: "Run a detached share worker", Hidden: true, Args: usage(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		decoder := json.NewDecoder(io.LimitReader(os.Stdin, 256<<10))
		var config shareWorkerConfig
		if err := decoder.Decode(&config); err != nil {
			return err
		}
		path, err := shareStatePath(config.Local.Server, config.Local.Request.RequestID)
		if err != nil || path != config.Path {
			return errors.New("invalid detached worker state path")
		}
		local, err := readShareLocal(path)
		if err != nil {
			return err
		}
		if local.WorkerID != config.Local.WorkerID || local.Nonce != config.Local.Nonce {
			return errors.New("detached worker identity does not match local state")
		}
		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()
		acknowledged := make(chan error, 1)
		go func() {
			var ack shareWorkerAck
			err := decoder.Decode(&ack)
			if err == nil && ack.Type != "ack" {
				err = errors.New("parent cancelled detached startup")
			}
			if err != nil {
				cancel()
			}
			acknowledged <- err
		}()
		encoder := json.NewEncoder(os.Stdout)
		c, err := authed(ctx)
		if err == nil && c.Server != local.Server {
			err = errors.New("coordinator configuration changed during share startup")
		}
		if err == nil {
			err = runShareLocal(ctx, c, local, func(publisherCtx context.Context, s *api.Share) error {
				return acceptShareHandoff(publisherCtx, acknowledged, encoder, local, s)
			})
		}
		if err != nil {
			code, status := classify(err)
			current := local.snapshot()
			message := shareWorkerMessage{Type: "error", Error: err.Error(), Code: code, Status: status}
			if current.Share != nil {
				message.ShareID = current.Share.ID
			}
			_ = encoder.Encode(message)
			_ = updateShareLocal(local, "ended", nil, err.Error())
			return err
		}
		return nil
	}}
}

func acceptShareHandoff(ctx context.Context, acknowledged <-chan error, encoder *json.Encoder, local *shareLocal, s *api.Share) error {
	if err := updateShareLocal(local, "proposed", s, ""); err != nil {
		return err
	}
	out := shareResult(s, local.snapshot())
	if err := encoder.Encode(shareWorkerMessage{Type: "proposed", Output: &out}); err != nil {
		return err
	}
	timer := time.NewTimer(time.Until(local.Request.StartupDeadline))
	defer timer.Stop()
	select {
	case err := <-acknowledged:
		if err != nil {
			return fmt.Errorf("detached ownership was not acknowledged: %w", err)
		}
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("detached ownership acknowledgement timed out")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !time.Now().Before(local.Request.StartupDeadline) {
		return errors.New("detached ownership deadline passed")
	}
	if err := commitShareHandoff(ctx, local, s); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	out = shareResult(s, local.snapshot())
	// Ownership is already committed. A lost final pipe write is recovered by
	// operation lookup/private state rather than silently ending a ready share.
	_ = encoder.Encode(shareWorkerMessage{Type: "accepted", Output: &out})
	return nil
}

func commitShareHandoff(ctx context.Context, local *shareLocal, s *api.Share) error {
	local.mu.Lock()
	defer local.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if local.State == "ended" {
		return errors.New("publisher ended before ownership handoff")
	}
	if !time.Now().Before(local.Request.StartupDeadline) {
		return errors.New("detached ownership deadline passed")
	}
	local.State, local.Share = "ready", s
	return writeShareLocalLocked(local)
}

func detachShare(parent context.Context, local *shareLocal) (shareOutput, error) {
	executable, err := os.Executable()
	if err != nil {
		return shareOutput{}, err
	}
	command := shareWorkerCommand(executable)
	configureShareProcess(command)
	command.Env = append(os.Environ(), "TUNNELER_NO_UPDATE_CHECK=1")
	logFile, err := os.OpenFile(filepath.Join(filepath.Dir(local.Path), "worker.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return shareOutput{}, err
	}
	defer logFile.Close()
	command.Stderr = logFile
	stdin, err := command.StdinPipe()
	if err != nil {
		return shareOutput{}, err
	}
	defer stdin.Close()
	stdout, childStdout, err := os.Pipe()
	if err != nil {
		return shareOutput{}, err
	}
	defer stdout.Close()
	defer childStdout.Close()
	command.Stdout = childStdout
	if err := command.Start(); err != nil {
		_ = updateShareLocal(local, "ended", nil, err.Error())
		return shareOutput{}, err
	}
	childStdout.Close()
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	accepted := false
	ackSent := false
	defer func() {
		if !accepted && !ackSent {
			_ = json.NewEncoder(stdin).Encode(shareWorkerAck{Type: "cancel"})
			stdin.Close()
			cancelCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = stopShareLocal(cancelCtx, local)
			cancel()
			select {
			case <-waited:
			case <-time.After(5 * time.Second):
				// This is the child started by this invocation, not a cached PID.
				_ = command.Process.Kill()
			}
		}
	}()
	if err := json.NewEncoder(stdin).Encode(shareWorkerConfig{local.shareLocalData, local.Path}); err != nil {
		return shareOutput{}, err
	}
	type decoded struct {
		message shareWorkerMessage
		err     error
	}
	messages := make(chan decoded)
	ctx, cancel := context.WithDeadline(parent, local.Request.StartupDeadline)
	defer cancel()
	go func() {
		decoder := json.NewDecoder(io.LimitReader(stdout, 256<<10))
		for {
			var message shareWorkerMessage
			err := decoder.Decode(&message)
			select {
			case messages <- decoded{message, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			if ackSent {
				if out, ok := discoverCommittedShare(local); ok {
					accepted = true
					return out, nil
				}
			}
			current, _ := readShareLocal(local.Path)
			failure := shareError{error: errors.New("detached startup timed out; inspect the request ID for its outcome"), code: "startup_timeout", status: exitUnavailable, requestID: local.Request.RequestID}
			if current != nil && current.Share != nil {
				failure.shareID = current.Share.ID
			}
			return shareOutput{}, failure
		case received := <-messages:
			if received.err != nil {
				if ackSent {
					if out, ok := discoverCommittedShare(local); ok {
						accepted = true
						return out, nil
					}
				}
				return shareOutput{}, shareError{error: fmt.Errorf("detached worker ended before confirmed handoff: %w", received.err), code: "startup_failed", status: exitUnavailable, requestID: local.Request.RequestID}
			}
			msg := received.message
			switch msg.Type {
			case "proposed":
				if msg.Output == nil {
					return shareOutput{}, errors.New("worker readiness is missing metadata")
				}
				if err := json.NewEncoder(stdin).Encode(shareWorkerAck{Type: "ack"}); err != nil {
					return shareOutput{}, err
				}
				ackSent = true
			case "accepted":
				if msg.Output == nil || msg.Output.State != "ready" {
					return shareOutput{}, errors.New("worker accepted without ready metadata")
				}
				accepted = true
				return *msg.Output, nil
			case "error":
				return shareOutput{}, shareError{error: errors.New(msg.Error), code: msg.Code, status: msg.Status, shareID: msg.ShareID, requestID: local.Request.RequestID}
			default:
				return shareOutput{}, fmt.Errorf("invalid detached worker message %q", msg.Type)
			}
		}
	}
}

func discoverCommittedShare(local *shareLocal) (shareOutput, bool) {
	current, err := readShareLocal(local.Path)
	if err != nil || current.State != "ready" || current.Share == nil {
		return shareOutput{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reply, err := shareIPC(ctx, current, "inspect")
	if err != nil || reply.Local == nil || reply.Local.State != "ready" || reply.Local.Share == nil || reply.Local.WorkerID != local.WorkerID {
		return shareOutput{}, false
	}
	return shareResult(reply.Local.Share, &shareLocal{shareLocalData: *reply.Local}), true
}
