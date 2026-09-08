package portal

import (
	"context"
	"net/http"
	"slices"
	"time"
)

// Revocation records that an issued credential should no longer be honoured.
type Revocation struct {
	Serial string
	Kind   Kind
	User   string
	At     time.Time
	// Until is when the certificate would have expired anyway. Past it the
	// entry can be dropped: the credential is dead either way, and a
	// revocation list that only grows is its own problem.
	Until time.Time
}

// Revoker is the optional half of a Store. A Store without it simply cannot
// revoke, and the portal says so rather than pretending.
type Revoker interface {
	Revoke(ctx context.Context, r Revocation) error
	Revocations(ctx context.Context, kind Kind) ([]Revocation, error)
}

var _ Revoker = (*MemoryStore)(nil)

func (s *MemoryStore) Revoke(_ context.Context, r Revocation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !slices.ContainsFunc(s.revoked, func(e Revocation) bool { return e.Serial == r.Serial }) {
		s.revoked = append(s.revoked, r)
	}
	s.pruneRevoked(time.Now())
	return nil
}

func (s *MemoryStore) Revocations(_ context.Context, kind Kind) ([]Revocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneRevoked(time.Now())

	var out []Revocation
	for _, r := range s.revoked {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out, nil
}

// pruneRevoked drops entries whose certificate has expired. Callers hold s.mu.
func (s *MemoryStore) pruneRevoked(now time.Time) {
	s.revoked = slices.DeleteFunc(s.revoked, func(r Revocation) bool {
		return now.After(r.Until)
	})
}

func (p *Portal) handleRevoke(w http.ResponseWriter, r *http.Request) {
	id := p.identify(r)
	if id.Username == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	revoker, ok := p.sessions.(Revoker)
	if !ok {
		http.Error(w, "revocation is not available", http.StatusNotImplemented)
		return
	}

	// Look the serial up among the caller's own sessions. A serial is not a
	// capability, so this is what stops one user revoking another's credential
	// by guessing it.
	serial := r.PathValue("serial")
	mine, err := p.sessions.For(r.Context(), id.Username)
	if err != nil {
		p.log.ErrorContext(r.Context(), "read sessions", "user", id.Username, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	i := slices.IndexFunc(mine, func(s Session) bool { return s.Serial == serial })
	if i < 0 {
		p.log.WarnContext(r.Context(), "denied revocation", "user", id.Username, "serial", serial)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	session := mine[i]

	if err := revoker.Revoke(r.Context(), Revocation{
		Serial: session.Serial,
		Kind:   session.Kind,
		User:   session.User,
		At:     time.Now(),
		Until:  session.ExpiresAt,
	}); err != nil {
		p.log.ErrorContext(r.Context(), "revoke", "serial", serial, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	p.log.InfoContext(r.Context(), "revoked credential",
		"user", session.User, "profile", session.Profile,
		"kind", session.Kind, "serial", session.Serial)

	// The revocation is recorded either way; failing to write the list out is
	// an operational problem, not a reason to tell the user it did not happen.
	if err := p.publishRevocations(r.Context()); err != nil {
		p.log.ErrorContext(r.Context(), "publish revocation list", "error", err)
	}

	http.Redirect(w, r, "/issued", http.StatusSeeOther)
}
