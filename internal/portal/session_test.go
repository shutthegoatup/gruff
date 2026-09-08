package portal

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestSessionStoreScopesToUser(t *testing.T) {
	t.Parallel()

	var s MemoryStore
	expires := time.Now().Add(time.Hour)
	s.add(t, Session{User: "alice", Profile: "livedata", ExpiresAt: expires})
	s.add(t, Session{User: "bob", Profile: "secret", ExpiresAt: expires})

	alice := s.forUser(t, "alice")
	if len(alice) != 1 {
		t.Fatalf("For(alice) returned %d sessions, want 1", len(alice))
	}
	if alice[0].Profile != "livedata" {
		t.Errorf("For(alice) returned bob's session: %+v", alice[0])
	}
	if got := s.forUser(t, "nobody"); len(got) != 0 {
		t.Errorf("For(nobody) returned %d sessions, want 0", len(got))
	}
}

func TestSessionStoreReturnsNewestFirst(t *testing.T) {
	t.Parallel()

	var s MemoryStore
	expires := time.Now().Add(time.Hour)
	for _, p := range []string{"first", "second", "third"} {
		s.add(t, Session{User: "alice", Profile: p, ExpiresAt: expires})
	}

	got := s.forUser(t, "alice")
	if len(got) != 3 {
		t.Fatalf("got %d sessions, want 3", len(got))
	}
	if got[0].Profile != "third" {
		t.Errorf("newest session = %q, want %q", got[0].Profile, "third")
	}
}

// Expired sessions must fall out of the audit list rather than accumulate for
// the life of the process.
func TestSessionStoreEvictsExpired(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var s MemoryStore
		s.add(t, Session{User: "alice", Profile: "short", ExpiresAt: time.Now().Add(time.Hour)})
		s.add(t, Session{User: "alice", Profile: "long", ExpiresAt: time.Now().Add(8 * time.Hour)})

		if got := s.forUser(t, "alice"); len(got) != 2 {
			t.Fatalf("got %d sessions, want 2", len(got))
		}

		time.Sleep(2 * time.Hour)

		got := s.forUser(t, "alice")
		if len(got) != 1 {
			t.Fatalf("after 2h got %d sessions, want 1", len(got))
		}
		if got[0].Profile != "long" {
			t.Errorf("surviving session = %q, want %q", got[0].Profile, "long")
		}

		time.Sleep(8 * time.Hour)

		if got := s.forUser(t, "alice"); len(got) != 0 {
			t.Errorf("after 10h got %d sessions, want 0", len(got))
		}
	})
}

func TestSessionStoreIsBounded(t *testing.T) {
	t.Parallel()

	var s MemoryStore
	expires := time.Now().Add(time.Hour)
	for i := range maxSessions * 2 {
		s.add(t, Session{User: "alice", Profile: fmt.Sprintf("p%d", i), ExpiresAt: expires})
	}

	got := s.forUser(t, "alice")
	if len(got) != maxSessions {
		t.Errorf("got %d sessions, want the store capped at %d", len(got), maxSessions)
	}
	// The cap must drop the oldest, not the newest.
	if want := fmt.Sprintf("p%d", maxSessions*2-1); got[0].Profile != want {
		t.Errorf("newest session = %q, want %q", got[0].Profile, want)
	}
}

// The store is reached concurrently by every in-flight request; run under -race.
func TestSessionStoreConcurrentAccess(t *testing.T) {
	t.Parallel()

	var s MemoryStore
	var wg sync.WaitGroup
	expires := time.Now().Add(time.Hour)

	for i := range 50 {
		wg.Add(2)
		// t.Fatalf is illegal off the test goroutine, so these call the
		// interface directly rather than through the helpers.
		go func() {
			defer wg.Done()
			if err := s.Add(context.Background(), Session{User: fmt.Sprintf("user%d", i%5), ExpiresAt: expires}); err != nil {
				t.Errorf("Add(): %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := s.For(context.Background(), fmt.Sprintf("user%d", i%5)); err != nil {
				t.Errorf("For(): %v", err)
			}
		}()
	}
	wg.Wait()

	total := 0
	for i := range 5 {
		total += len(s.forUser(t, fmt.Sprintf("user%d", i)))
	}
	if total != 50 {
		t.Errorf("recorded %d sessions, want 50", total)
	}
}

// add and forUser keep the tests readable now that Store carries a context and
// an error the in-memory implementation never returns.
func (s *MemoryStore) add(t *testing.T, session Session) {
	t.Helper()
	if err := s.Add(context.Background(), session); err != nil {
		t.Fatalf("Add(): %v", err)
	}
}

func (s *MemoryStore) forUser(t *testing.T, user string) []Session {
	t.Helper()
	got, err := s.For(context.Background(), user)
	if err != nil {
		t.Fatalf("For(%q): %v", user, err)
	}
	return got
}
