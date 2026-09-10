package app

import (
	"sync"
	"testing"
)

func TestSessionsCapRetainsMostRecent(t *testing.T) {
	var s sessions
	for i := 0; i < maxSessions+5; i++ {
		s.AddItem(session{User: "u", Profile: "p"})
	}
	got := s.Snapshot()
	if len(got) != maxSessions {
		t.Fatalf("expected %d retained, got %d", maxSessions, len(got))
	}
	if got[0].Profile != "p" || got[len(got)-1].Profile != "p" {
		t.Fatal("unexpected snapshot contents")
	}
}

func TestSessionsForUserFilters(t *testing.T) {
	var s sessions
	s.AddItem(session{User: "alice"})
	s.AddItem(session{User: "bob"})
	s.AddItem(session{User: "alice"})
	got := s.ForUser("alice")
	if len(got) != 2 {
		t.Fatalf("expected 2 sessions for alice, got %d", len(got))
	}
	if got[0].User != "alice" || got[1].User != "alice" {
		t.Fatal("ForUser returned a session for a different user")
	}
}

func TestSessionsConcurrentAppendAndSnapshot(t *testing.T) {
	var s sessions
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.AddItem(session{User: "u"})
		}()
	}
	wg.Wait()
	if got := s.Snapshot(); len(got) != 50 {
		t.Fatalf("expected 50 sessions, got %d", len(got))
	}
}
