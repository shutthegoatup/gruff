package app

import "sync"

// maxSessions bounds the retained audit list so memory doesn't grow unbounded.
const maxSessions = 1000

type session struct {
	IssuedOn    string
	User        string
	Profile     string
	Duration    string
	ExpiresOn   string
	ClientIP    string
	IssuingCA   string
	Certificate string
	PrivateKey  string
}

type sessions struct {
	mu    sync.Mutex
	Items []session
}

// AddItem appends an issued session, capping the retained audit list so memory
// doesn't grow unbounded. It returns the updated slice.
func (s *sessions) AddItem(mySession session) []session {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Items = append(s.Items, mySession)
	if len(s.Items) > maxSessions {
		s.Items = s.Items[len(s.Items)-maxSessions:]
	}
	return s.Items
}

// Snapshot returns a copy of the retained sessions, so callers never read the
// slice concurrently with an append.
func (s *sessions) Snapshot() []session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]session, len(s.Items))
	copy(out, s.Items)
	return out
}

// ForUser returns the sessions issued to the given username, oldest first.
func (s *sessions) ForUser(username string) []session {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []session
	for _, it := range s.Items {
		if it.User == username {
			out = append(out, it)
		}
	}
	return out
}
