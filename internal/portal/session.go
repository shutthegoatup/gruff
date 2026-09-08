package portal

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"
)

// maxSessions bounds the in-memory audit list so that a long-running process
// cannot be driven to exhaust memory by repeated issuance.
const maxSessions = 1000

// Kind distinguishes what an issued certificate grants.
type Kind string

const (
	KindVPN Kind = "vpn"
	KindSSH Kind = "ssh"
)

// Session records that a certificate was issued. It deliberately holds no key
// material: the private key exists only for the life of the response that
// carries it to the client.
type Session struct {
	User      string
	Profile   string
	Kind      Kind
	Serial    string
	ClientIP  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Expired reports whether the issued certificate is no longer valid at t.
func (s Session) Expired(t time.Time) bool { return t.After(s.ExpiresAt) }

// Remaining is the time left before the certificate expires, in a compact form
// suited to a badge: "8m", "2h", "1h 42m".
func (s Session) Remaining() string {
	d := time.Until(s.ExpiresAt).Round(time.Minute)
	if d <= 0 {
		return "expired"
	}

	h, m := int(d.Hours()), int(d.Minutes())%60
	switch {
	case h == 0:
		return fmt.Sprintf("%dm", m)
	case m == 0:
		return fmt.Sprintf("%dh", h)
	default:
		return fmt.Sprintf("%dh %dm", h, m)
	}
}

// Expiring reports whether the session is close enough to expiry to highlight.
func (s Session) Expiring() bool {
	return time.Until(s.ExpiresAt) < 15*time.Minute
}

// ShortSerial abbreviates the certificate serial for display; the full value is
// in the issuance log.
func (s Session) ShortSerial() string {
	const shown = 12
	if len(s.Serial) <= shown {
		return s.Serial
	}
	return s.Serial[:shown] + "…"
}

// Store records issued credentials.
//
// This is an audit aid, not a source of truth: nothing about a certificate's
// validity depends on it, and losing it costs visibility rather than access.
// That is what makes the in-memory default defensible, and it is also why the
// interface exists - a deployment that wants the record to survive a restart
// can back it with SQLite or Postgres without any other code changing.
//
// Add failing must never fail an issuance: the certificate is already minted
// by the time it is called.
type Store interface {
	Add(ctx context.Context, s Session) error
	For(ctx context.Context, user string) ([]Session, error)
}

// MemoryStore is the default Store: newest first, capped, expiry-pruned, and
// gone when the process is.
type MemoryStore struct {
	mu       sync.Mutex
	sessions []Session
}

var _ Store = (*MemoryStore)(nil)

// Add records an issued certificate, dropping expired and surplus entries.
func (s *MemoryStore) Add(_ context.Context, session Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions = append([]Session{session}, s.sessions...)
	s.prune(time.Now())
	return nil
}

// For returns the unexpired sessions belonging to user, newest first.
func (s *MemoryStore) For(_ context.Context, user string) ([]Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.prune(time.Now())

	var out []Session
	for _, session := range s.sessions {
		if session.User == user {
			out = append(out, session)
		}
	}
	return out, nil
}

// prune drops expired entries and caps the list. Callers must hold s.mu.
func (s *MemoryStore) prune(now time.Time) {
	s.sessions = slices.DeleteFunc(s.sessions, func(session Session) bool {
		return session.Expired(now)
	})
	if len(s.sessions) > maxSessions {
		clear(s.sessions[maxSessions:])
		s.sessions = s.sessions[:maxSessions]
	}
}
