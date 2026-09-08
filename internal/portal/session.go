package portal

import (
	"fmt"
	"slices"
	"sync"
	"time"
)

// maxSessions bounds the audit list so that a long-running process cannot be
// driven to exhaust memory by repeated issuance.
const maxSessions = 1000

// Session records that a certificate was issued. It deliberately holds no key
// material: the private key exists only for the life of the response that
// carries it to the client.
type Session struct {
	User      string
	Profile   string
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

// SessionStore is an in-memory record of issued certificates, newest first.
//
// It is an audit aid, not a source of truth: it does not survive a restart, and
// nothing about certificate validity depends on it.
type SessionStore struct {
	mu       sync.Mutex
	sessions []Session
}

// Add records an issued certificate, dropping expired and surplus entries.
func (s *SessionStore) Add(session Session) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions = append([]Session{session}, s.sessions...)
	s.prune(time.Now())
}

// For returns the unexpired sessions belonging to user, newest first.
func (s *SessionStore) For(user string) []Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.prune(now)

	var out []Session
	for _, session := range s.sessions {
		if session.User == user {
			out = append(out, session)
		}
	}
	return out
}

// prune drops expired entries and caps the list. Callers must hold s.mu.
func (s *SessionStore) prune(now time.Time) {
	s.sessions = slices.DeleteFunc(s.sessions, func(session Session) bool {
		return session.Expired(now)
	})
	if len(s.sessions) > maxSessions {
		clear(s.sessions[maxSessions:])
		s.sessions = s.sessions[:maxSessions]
	}
}
