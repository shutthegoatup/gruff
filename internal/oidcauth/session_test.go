package oidcauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shutthegoatup/gruff/internal/config"
	"github.com/shutthegoatup/gruff/internal/oidcauth/oidctest"
)

// session-lifetime is the knob operators set, so it has to be the thing that
// decides. Providers issue short ID tokens - Keycloak defaults to five minutes
// - and an ID token's exp bounds how long that assertion may be presented, not
// how long the session it produced should last.
func TestSessionHonoursConfiguredLifetime(t *testing.T) {
	t.Parallel()

	idp := oidctest.New(t)
	idp.TokenLifetime = 5 * time.Minute // as a real provider would

	auth, codec := newAuth(t, idp)
	auth.cfg.SessionLifetime = durationOf(8 * time.Hour)

	session, _ := login(t, auth, idp, "/")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(session)
	user, err := codec.Open(r)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	remaining := time.Until(user.Expires)
	if remaining < 7*time.Hour {
		t.Errorf("session lasts %s; a five-minute ID token should not shorten an eight-hour session", remaining)
	}
}

// The cookie's own attributes must agree with the sealed deadline, or the
// browser drops a session the server still considers valid.
func TestSessionCookieMatchesItsPayload(t *testing.T) {
	t.Parallel()

	idp := oidctest.New(t)
	idp.TokenLifetime = 5 * time.Minute

	auth, codec := newAuth(t, idp)
	auth.cfg.SessionLifetime = durationOf(2 * time.Hour)

	session, _ := login(t, auth, idp, "/")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(session)
	user, err := codec.Open(r)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if drift := session.Expires.Sub(user.Expires); drift > time.Second || drift < -time.Second {
		t.Errorf("cookie expiry and sealed deadline differ by %s", drift)
	}
	if session.MaxAge < int((90 * time.Minute).Seconds()) {
		t.Errorf("Max-Age = %ds, want about two hours", session.MaxAge)
	}
}

func durationOf(d time.Duration) config.Duration { return config.Duration(d) }
