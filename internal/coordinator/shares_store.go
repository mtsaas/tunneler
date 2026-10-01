package coordinator

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
)

func (m *shareManager) loadLedger() error {
	if _, err := m.c.store.db.Exec(`CREATE TABLE IF NOT EXISTS share_routing (id INTEGER PRIMARY KEY CHECK(id = 1), metadata TEXT NOT NULL) STRICT`); err != nil {
		return err
	}
	if m.routing != nil {
		if err := m.saveRoutingLocked(*m.routing); err != nil {
			return err
		}
	} else {
		var metadata string
		err := m.c.store.db.QueryRow(`SELECT metadata FROM share_routing WHERE id = 1`).Scan(&metadata)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil {
			var routing shareRoutingMetadata
			if err := json.Unmarshal([]byte(metadata), &routing); err != nil {
				return err
			}
			m.routing = &SharingConfig{Domain: routing.Domain, ControlHosts: routing.ControlHosts}
		}
	}
	_, err := m.c.store.db.Exec(`CREATE TABLE IF NOT EXISTS share_operations (
		share_id TEXT PRIMARY KEY,
		issuer TEXT NOT NULL,
		subject TEXT NOT NULL,
		request_id TEXT NOT NULL,
		fingerprint TEXT NOT NULL,
		metadata TEXT NOT NULL,
		retain_until INTEGER NOT NULL,
		UNIQUE(issuer, subject, request_id)
	) STRICT`)
	if err != nil {
		return err
	}
	rows, err := m.c.store.db.Query(`SELECT issuer, subject, fingerprint, metadata, retain_until FROM share_operations`)
	if err != nil {
		return err
	}
	var restored []*sharedServiceSet
	for rows.Next() {
		s := &sharedServiceSet{manager: m}
		var metadata string
		var retention int64
		if err := rows.Scan(&s.owner.Issuer, &s.owner.Subject, &s.fingerprint, &metadata, &retention); err != nil {
			rows.Close()
			return err
		}
		if err := json.Unmarshal([]byte(metadata), &s.info); err != nil {
			rows.Close()
			return err
		}
		s.owner.Username = s.info.Owner
		if retention != 0 {
			s.retainUntil = time.Unix(0, retention)
		}
		restored = append(restored, s)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	now := time.Now()
	for _, s := range restored {
		s.ctx, s.cancel = context.WithCancel(context.Background())
		s.cancel()
		if s.info.State != "ended" {
			s.info.State, s.info.TerminalReason = "ended", "coordinator_restart"
			s.retainUntil = now.Add(time.Duration(m.c.config().sharingConfig().OperationRetention))
			if err := m.saveLedgerLocked(s, false); err != nil {
				return err
			}
		}
		m.shares[s.info.ID] = s
		m.operations[shareOperationKey(&s.owner, s.info.RequestID)] = s
	}
	return m.pruneLedgerLocked(now)
}

// Keep host isolation across disabling and restarting sharing while wildcard
// DNS may still direct retired preview URLs to this coordinator.
type shareRoutingMetadata struct {
	Domain       string   `json:"domain"`
	ControlHosts []string `json:"control_hosts"`
}

func (m *shareManager) saveRoutingLocked(routing SharingConfig) error {
	metadata, err := json.Marshal(shareRoutingMetadata{Domain: routing.Domain, ControlHosts: routing.ControlHosts})
	if err != nil {
		return err
	}
	_, err = m.c.store.db.Exec(`INSERT INTO share_routing (id, metadata) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET metadata = excluded.metadata`, string(metadata))
	return err
}

func (m *shareManager) saveLedgerLocked(s *sharedServiceSet, insert bool) error {
	metadata, err := json.Marshal(s.info)
	if err != nil {
		return err
	}
	retention := int64(0)
	if !s.retainUntil.IsZero() {
		retention = s.retainUntil.UnixNano()
	}
	if insert {
		_, err = m.c.store.db.Exec(`INSERT INTO share_operations (share_id, issuer, subject, request_id, fingerprint, metadata, retain_until) VALUES (?, ?, ?, ?, ?, ?, ?)`, s.info.ID, s.owner.Issuer, s.owner.Subject, s.info.RequestID, s.fingerprint, string(metadata), retention)
	} else {
		_, err = m.c.store.db.Exec(`UPDATE share_operations SET metadata = ?, retain_until = ? WHERE share_id = ?`, string(metadata), retention, s.info.ID)
	}
	return err
}

func (m *shareManager) pruneLedgerLocked(now time.Time) error {
	if _, err := m.c.store.db.Exec(`DELETE FROM share_operations WHERE retain_until != 0 AND retain_until <= ?`, now.UnixNano()); err != nil {
		return err
	}
	for shareID, s := range m.shares {
		if s.info.State == "ended" && !s.retainUntil.IsZero() && !now.Before(s.retainUntil) {
			delete(m.shares, shareID)
			delete(m.operations, shareOperationKey(&s.owner, s.info.RequestID))
		}
	}
	return nil
}

func (m *shareManager) inspect(id *Identity, shareID string, admin bool) (*api.Share, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.pruneLedgerLocked(time.Now()); err != nil {
		return nil, err
	}
	s, err := m.findLocked(id, shareID, admin)
	if err != nil {
		return nil, err
	}
	if reason := s.expiredReasonLocked(time.Now()); reason != "" {
		m.mu.Unlock()
		s.end(reason)
		m.mu.Lock()
	}
	info := cloneShare(s.info)
	return &info, nil
}

func (m *shareManager) operation(id *Identity, requestID string) (*api.Share, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.pruneLedgerLocked(time.Now()); err != nil {
		return nil, err
	}
	s := m.operations[shareOperationKey(id, requestID)]
	if s == nil {
		return nil, shareAPIError(404, "unknown_share", "operation is unknown or its retention window expired")
	}
	if reason := s.expiredReasonLocked(time.Now()); reason != "" {
		m.mu.Unlock()
		s.end(reason)
		m.mu.Lock()
	}
	info := cloneShare(s.info)
	return &info, nil
}
