package portal

import (
	"strconv"
	"testing"
	"time"
)

// The sweep used to read b.tokens, which is only as current as b.last. A user
// who hit the limit and never returned left a bucket recorded as empty, so the
// condition never held and the entry stayed for the life of the process - for
// exactly the callers worth forgetting.
func TestLimiterForgetsUsersWhoHitTheLimit(t *testing.T) {
	t.Parallel()

	l := newLimiter(2)
	start := time.Now()

	const users = 2000
	for i := range users {
		key := strconv.Itoa(i)
		for range 3 {
			l.allow(key, start)
		}
	}
	if got := len(l.buckets); got != users {
		t.Fatalf("tracking %d users, want %d", got, users)
	}

	l.allow("someone-else", start.Add(24*time.Hour))

	// Only the caller that just arrived; every other bucket has long since
	// refilled to full, so keeping it says nothing a fresh one would not.
	if got := len(l.buckets); got != 1 {
		t.Errorf("still tracking %d users a day later, want 1", got)
	}
}

// Forgetting a bucket must not forget a limit that is still biting.
func TestLimiterKeepsBucketsStillInUse(t *testing.T) {
	t.Parallel()

	l := newLimiter(2)
	start := time.Now()

	for i := range 2000 {
		l.allow(strconv.Itoa(i), start)
	}

	// Spend alice's allowance, then push the map over the sweep threshold
	// again a minute later - well inside her refill window.
	for range 3 {
		l.allow("alice", start)
	}
	later := start.Add(time.Minute)
	l.allow("bob", later)

	if allowed, _ := l.allow("alice", later); allowed {
		t.Error("alice was allowed again a minute after exhausting her allowance")
	}
}
