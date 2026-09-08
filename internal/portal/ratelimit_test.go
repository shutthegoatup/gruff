package portal

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestLimiterAllowsUpToTheCap(t *testing.T) {
	t.Parallel()

	l := newLimiter(5)
	now := time.Now()

	for i := range 5 {
		if ok, _ := l.allow("alice", now); !ok {
			t.Fatalf("call %d was refused within the cap", i+1)
		}
	}
	ok, wait := l.allow("alice", now)
	if ok {
		t.Error("the sixth call was allowed past a cap of 5")
	}
	if wait <= 0 {
		t.Errorf("Retry-After = %s, want a positive wait", wait)
	}
}

func TestLimiterIsPerUser(t *testing.T) {
	t.Parallel()

	l := newLimiter(2)
	now := time.Now()

	l.allow("alice", now)
	l.allow("alice", now)
	if ok, _ := l.allow("alice", now); ok {
		t.Fatal("alice was not limited")
	}
	if ok, _ := l.allow("bob", now); !ok {
		t.Error("bob was limited by alice's usage")
	}
}

func TestLimiterRefills(t *testing.T) {
	t.Parallel()

	l := newLimiter(60) // one per minute
	start := time.Now()

	for range 60 {
		l.allow("alice", start)
	}
	if ok, _ := l.allow("alice", start); ok {
		t.Fatal("not limited after spending the whole budget")
	}

	if ok, _ := l.allow("alice", start.Add(30*time.Second)); ok {
		t.Error("allowed after 30s, when the refill rate is one per minute")
	}
	if ok, _ := l.allow("alice", start.Add(90*time.Second)); !ok {
		t.Error("still limited after 90s, when a token should have refilled")
	}
}

// The bucket must not refill past its cap, or an idle user accrues an
// unbounded burst.
func TestLimiterDoesNotOverfill(t *testing.T) {
	t.Parallel()

	l := newLimiter(3)
	start := time.Now()

	l.allow("alice", start)
	// A week later the bucket is full, not enormous.
	later := start.Add(7 * 24 * time.Hour)
	for i := range 3 {
		if ok, _ := l.allow("alice", later); !ok {
			t.Fatalf("call %d refused on a refilled bucket", i+1)
		}
	}
	if ok, _ := l.allow("alice", later); ok {
		t.Error("bucket refilled past its cap")
	}
}

func TestLimiterDisabled(t *testing.T) {
	t.Parallel()

	l := newLimiter(0)
	if l != nil {
		t.Fatal("a zero cap should disable the limiter")
	}
	for range 1000 {
		if ok, _ := l.allow("alice", time.Now()); !ok {
			t.Fatal("a disabled limiter refused a call")
		}
	}
}

// End to end: issuance stops once the budget is spent, with a Retry-After the
// client can act on.
func TestIssueIsRateLimited(t *testing.T) {
	t.Parallel()

	h := newTestPortalWithLimit(t, 3)

	for i := range 3 {
		w := request(t, h, http.MethodPost, "/profile/livedata/issue", "alice", "vpn-livedata")
		if w.Code != http.StatusOK {
			t.Fatalf("issue %d: status %d", i+1, w.Code)
		}
	}

	w := request(t, h, http.MethodPost, "/profile/livedata/issue", "alice", "vpn-livedata")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	if w.Body.String() == "" || len(w.Body.String()) == 0 {
		t.Error("no explanation in the 429 body")
	}

	retry := w.Header().Get("Retry-After")
	if retry == "" {
		t.Fatal("no Retry-After header")
	}
	if n, err := strconv.Atoi(retry); err != nil || n <= 0 {
		t.Errorf("Retry-After = %q, want positive seconds", retry)
	}
}

// The budget is shared across credential types: it bounds a client, not a
// particular endpoint.
func TestRateLimitSpansVPNAndSSH(t *testing.T) {
	t.Parallel()

	h := newTestPortalWithLimit(t, 2)

	if w := request(t, h, http.MethodPost, "/profile/livedata/issue", "alice", "vpn-livedata,ssh-bastion"); w.Code != http.StatusOK {
		t.Fatalf("vpn issue: status %d", w.Code)
	}
	if w := request(t, h, http.MethodPost, "/ssh/bastion/issue", "alice", "vpn-livedata,ssh-bastion"); w.Code != http.StatusOK {
		t.Fatalf("ssh issue: status %d", w.Code)
	}

	w := request(t, h, http.MethodPost, "/ssh/bastion/issue", "alice", "vpn-livedata,ssh-bastion")
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 once the shared budget is spent", w.Code)
	}
}

// A denied request must not spend the caller's budget, or a misconfigured role
// would lock someone out of the profiles they do hold.
func TestRateLimitNotSpentOnDeniedRequests(t *testing.T) {
	t.Parallel()

	h := newTestPortalWithLimit(t, 2)

	for range 5 {
		if w := request(t, h, http.MethodPost, "/profile/secret/issue", "alice", "vpn-livedata"); w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	}

	if w := request(t, h, http.MethodPost, "/profile/livedata/issue", "alice", "vpn-livedata"); w.Code != http.StatusOK {
		t.Errorf("status = %d; denied requests should not consume budget", w.Code)
	}
}
