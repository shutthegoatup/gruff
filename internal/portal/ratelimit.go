package portal

import (
	"maps"
	"math"
	"sync"
	"time"
)

// limiter caps how often one user may be issued a credential.
//
// It applies after authorization, so it bounds a runaway or compromised client
// rather than an attacker probing profile names - those never reach it. Each
// issuance is cheap on its own; the cost of a thousand is a thousand live
// credentials to reason about.
type limiter struct {
	perHour float64

	mu      sync.Mutex
	buckets map[string]*bucket
}

// bucket is a token bucket refilling at perHour, capped at its own burst.
type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perHour int) *limiter {
	if perHour <= 0 {
		return nil // disabled
	}
	return &limiter{perHour: float64(perHour), buckets: map[string]*bucket{}}
}

// allow consumes a token for key, reporting how long to wait if there is none.
func (l *limiter) allow(key string, now time.Time) (bool, time.Duration) {
	if l == nil {
		return true, 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.perHour, last: now}
		l.buckets[key] = b
	}

	perSecond := l.perHour / 3600
	b.tokens = math.Min(l.perHour, b.tokens+now.Sub(b.last).Seconds()*perSecond)
	b.last = now

	// Sweep whichever way this goes: an instance refusing everyone still needs
	// to drop the buckets it is no longer tracking anything for.
	defer l.sweep(now)

	if b.tokens < 1 {
		wait := time.Duration((1 - b.tokens) / perSecond * float64(time.Second))
		return false, wait.Round(time.Second)
	}

	b.tokens--
	return true, 0
}

// sweep drops buckets that have refilled completely, so an instance that has
// served many users does not hold one entry each forever. Callers hold l.mu.
func (l *limiter) sweep(now time.Time) {
	if len(l.buckets) < 1024 {
		return
	}
	maps.DeleteFunc(l.buckets, func(_ string, b *bucket) bool {
		return b.tokens >= l.perHour && now.Sub(b.last) > time.Hour
	})
}
