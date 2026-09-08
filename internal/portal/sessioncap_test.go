package portal

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// Revocation is authorized by finding the serial among the caller's own
// sessions, so a credential the store has forgotten cannot be revoked at all.
// The cap used to drop whichever entry was issued longest ago, which meant a
// long-lived certificate was given up to keep short-lived ones that would
// lapse on their own.
func TestStoreKeepsTheCredentialsWithTheMostLifeLeft(t *testing.T) {
	t.Parallel()

	s := &MemoryStore{}
	ctx := t.Context()
	now := time.Now()

	long := Session{
		User: "alice", Profile: "livedata", Kind: KindVPN, Serial: "LONG",
		IssuedAt: now, ExpiresAt: now.Add(8 * time.Hour),
	}
	if err := s.Add(ctx, long); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Then the list fills with credentials that expire far sooner.
	for i := range DefaultMaxSessions {
		if err := s.Add(ctx, Session{
			User: "bob" + strconv.Itoa(i), Profile: "notlivedata", Kind: KindVPN,
			Serial: strconv.Itoa(i), IssuedAt: now, ExpiresAt: now.Add(30 * time.Minute),
		}); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	mine, err := s.For(ctx, "alice")
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	if len(mine) != 1 {
		t.Fatalf("alice can see %d of her sessions, want 1: her certificate still has %s to run",
			len(mine), time.Until(long.ExpiresAt).Round(time.Minute))
	}
	if mine[0].Serial != "LONG" {
		t.Errorf("kept serial %q, want LONG", mine[0].Serial)
	}
}

// The bound is only defensible if an operator can see it biting.
func TestMetricsReportTheAuditListBound(t *testing.T) {
	t.Parallel()

	_, scrape := newTestPortalWithMetrics(t)
	body := scrape(t)

	for _, want := range []string{"gruff_sessions_tracked", "gruff_sessions_capacity"} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition does not report %s:\n%s", want, body)
		}
	}
	if !strings.Contains(body, "gruff_sessions_capacity 1000") {
		t.Errorf("capacity is not the default:\n%s", body)
	}
}

func TestStoreHonoursAConfiguredBound(t *testing.T) {
	t.Parallel()

	s := &MemoryStore{Max: 3}
	ctx := t.Context()
	now := time.Now()

	for i := range 10 {
		if err := s.Add(ctx, Session{
			User: "alice", Serial: strconv.Itoa(i),
			IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	held, limit, err := s.Tracked(ctx)
	if err != nil {
		t.Fatalf("Tracked: %v", err)
	}
	if held != 3 || limit != 3 {
		t.Errorf("Tracked() = %d of %d, want 3 of 3", held, limit)
	}
}
