package portal

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"sync"
	"time"
)

// DefaultMaxSessions bounds the in-memory audit list so that a long-running
// process cannot be driven to exhaust memory by repeated issuance.
//
// The bound is not free: a credential the store has forgotten cannot be revoked
// through the portal, since a revocation is authorized by finding the serial
// among the caller's own sessions. A deployment with more live credentials than
// this wants a larger one, which is what gruff_sessions_tracked is for.
const DefaultMaxSessions = 1000

// Kind distinguishes what an issued certificate grants.
type Kind string

const (
	KindVPN Kind = "vpn"
	KindSSH Kind = "ssh"
)

// Session records an issuance. It holds no key material: the private key lives
// only for the response that carries it.
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

// Store records issued credentials. It is an audit aid, not a source of truth:
// no certificate's validity depends on it, which is why an in-memory default is
// tolerable and why the seam exists for a durable one.
//
// A failing Add must never fail an issuance; the certificate is already minted.
type Store interface {
	Add(ctx context.Context, s Session) error
	For(ctx context.Context, user string) ([]Session, error)
	// All returns every unexpired session. It backs the administrator view and
	// is never reached without an admin role.
	All(ctx context.Context) ([]Session, error)
}

// MemoryStore is the default Store: newest first, capped, and gone with the
// process.
type MemoryStore struct {
	// Max is the most sessions to keep. Zero means DefaultMaxSessions.
	Max int

	mu       sync.Mutex
	sessions []Session
	revoked  []Revocation
}

func (s *MemoryStore) max() int {
	if s.Max <= 0 {
		return DefaultMaxSessions
	}
	return s.Max
}

// Tracked reports how many sessions are held and the bound they are held
// against, so an operator can see the cap approaching before it starts costing
// them revocations.
func (s *MemoryStore) Tracked(_ context.Context) (held, limit int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.prune(time.Now())
	return len(s.sessions), s.max(), nil
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

// All returns every unexpired session, newest first.
func (s *MemoryStore) All(_ context.Context) ([]Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.prune(time.Now())
	return slices.Clone(s.sessions), nil
}

// prune drops expired entries and caps the list. Callers must hold s.mu.
//
// Over the bound it gives up whichever credentials expire soonest, not whichever
// were issued longest ago. Those are not the same set once profiles have
// different lifetimes, and the difference decides which credentials can still be
// revoked: dropping an eight-hour certificate to keep a thousand half-hour ones
// is exactly the wrong trade.
func (s *MemoryStore) prune(now time.Time) {
	s.sessions = slices.DeleteFunc(s.sessions, func(session Session) bool {
		return session.Expired(now)
	})

	surplus := len(s.sessions) - s.max()
	if surplus <= 0 {
		return
	}

	order := make([]int, len(s.sessions))
	for i := range order {
		order[i] = i
	}
	// Soonest expiry goes first. The list is newest first, so a higher index is
	// an older entry: that is the tie-break when lifetimes match, which is the
	// ordinary case of one profile issuing everything.
	slices.SortStableFunc(order, func(a, b int) int {
		return cmp.Or(
			s.sessions[a].ExpiresAt.Compare(s.sessions[b].ExpiresAt),
			cmp.Compare(b, a),
		)
	})

	doomed := make(map[int]bool, surplus)
	for _, i := range order[:surplus] {
		doomed[i] = true
	}

	// Rebuilt in place, so the list stays newest first for display.
	kept := s.sessions[:0]
	for i, session := range s.sessions {
		if !doomed[i] {
			kept = append(kept, session)
		}
	}
	clear(s.sessions[len(kept):])
	s.sessions = kept
}
