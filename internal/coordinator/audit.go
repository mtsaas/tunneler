package coordinator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// auditHandler carries the access trail to the sink that keeps it. A record
// the sink fails to take is reported on the operational log, where an
// operator will see it, and the error goes on to whoever wrote the record:
// mustAudit's callers refuse the action that the record was for.
type auditHandler struct {
	slog.Handler
	log *slog.Logger
}

// Enabled lets every record through, whatever level the sink was built
// with: the trail is not complete without all of them.
func (h auditHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h auditHandler) Handle(ctx context.Context, r slog.Record) error {
	err := h.Handler.Handle(ctx, r)
	if err != nil {
		h.log.Error("the audit sink failed to take a record", "record", r.Message, "err", err)
	}
	return err
}

func (h auditHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return auditHandler{h.Handler.WithAttrs(attrs), h.log}
}

func (h auditHandler) WithGroup(name string) slog.Handler {
	return auditHandler{h.Handler.WithGroup(name), h.log}
}

// errUnaudited marks an action refused because its record was not kept.
var errUnaudited = errors.New("the audit trail could not record this, so it was refused")

// mustAudit writes a record that must be on the trail before the action it
// records may happen, and returns an error marked errUnaudited if the sink
// did not take it; the caller then refuses the action. A record of what has
// already happened is written with audit.Info and the like, since by then
// there is nothing left to refuse.
func mustAudit(ctx context.Context, audit *slog.Logger, msg string, args ...any) error {
	r := slog.NewRecord(time.Now(), slog.LevelInfo, msg, 0)
	r.Add(args...)
	if err := audit.Handler().Handle(ctx, r); err != nil {
		return fmt.Errorf("%w: %w", errUnaudited, err)
	}
	return nil
}
