package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"
)

// log carries everything the CLI has to say about what it is doing. It is
// replaced once flags are parsed; see newLogger.
var log = slog.New(statusHandler{w: os.Stderr, mu: new(sync.Mutex)})

// newLogger returns the process logger, which carries the timeline of what a
// command is doing; the result of a command is written by result instead.
// Servers always log JSON. The client prints plain, timestamped status lines
// for a person to read; with --output json it logs JSON to stderr, and with
// --verbose everything it does as structured text.
func newLogger(server, verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	switch {
	case server:
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	case outputJSON: // stdout is for results; the timeline goes to stderr
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	case verbose:
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(statusHandler{w: os.Stderr, mu: new(sync.Mutex)})
}

// statusHandler prints a record as a line of prose: the time and the
// message, and for problems the error. Other attributes are dropped, so
// messages at Info and above must read well on their own. Messages name
// clusters, services and accounts that the coordinator supplied, and errors
// carry what it said, so the line is made printable.
type statusHandler struct {
	w   io.Writer
	mu  *sync.Mutex
	min slog.Level // the zero value is Info
}

func (h statusHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.min }
func (h statusHandler) WithAttrs([]slog.Attr) slog.Handler           { return h }
func (h statusHandler) WithGroup(string) slog.Handler                { return h }

func (h statusHandler) Handle(_ context.Context, r slog.Record) error {
	line := r.Time.Format(time.TimeOnly) + "  " + r.Message
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "err" && a.Value.Any() != nil {
			line += ": " + a.Value.String()
		}
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := fmt.Fprintln(h.w, printable(line))
	return err
}
