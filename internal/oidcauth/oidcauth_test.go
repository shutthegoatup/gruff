package oidcauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/shutthegoatup/gruff/internal/authsession"
	"github.com/shutthegoatup/gruff/internal/config"
	"github.com/shutthegoatup/gruff/internal/oidcauth/oidctest"
)

func newAuth(t *testing.T, idp *oidctest.Provider) (*Authenticator, *authsession.Codec) {
	t.Helper()

	key, err := authsession.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	codec, err := authsession.NewCodec(key, false)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}

	auth, err := New(context.Background(), &config.Auth{
		Mode:            config.AuthOIDC,
		Issuer:          idp.Issuer,
		ClientID:        idp.ClientID,
		ClientSecret:    "shh",
		RedirectURL:     "http://127.0.0.1/auth/callback",
		RolesClaim:      "groups",
		UsernameClaim:   "preferred_username",
		InsecureCookies: true,
	}, codec)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return auth, codec
}

// start begins a login and returns the flow cookie plus the state the provider
// will echo back.
func start(t *testing.T, auth *Authenticator, next string) (*http.Cookie, url.Values) {
	t.Helper()

	authURL, cookie, err := auth.Start(next)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse authorize URL: %v", err)
	}
	return cookie, u.Query()
}

func callback(cookie *http.Cookie, query string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/auth/callback?"+query, nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}

func login(t *testing.T, auth *Authenticator, idp *oidctest.Provider, next string) (*http.Cookie, string) {
	t.Helper()

	cookie, q := start(t, auth, next)
	idp.Approve(q.Get("state"), q.Get("nonce"))

	session, target, err := auth.Complete(context.Background(),
		callback(cookie, "code=code-"+url.QueryEscape(q.Get("state"))+"&state="+url.QueryEscape(q.Get("state"))))
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	return session, target
}

func TestLogin(t *testing.T) {
	t.Parallel()

	idp := oidctest.New(t)
	auth, codec := newAuth(t, idp)

	session, target := login(t, auth, idp, "/ssh")
	if target != "/ssh" {
		t.Errorf("redirect = %q, want /ssh", target)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(session)

	user, err := codec.Open(r)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if user.Username != "alice.mercer" || user.Fullname != "Alice Mercer" {
		t.Errorf("identity = %+v", user)
	}
	if len(user.Roles) != 2 || user.Roles[0] != "vpn-livedata" {
		t.Errorf("roles = %v, want the groups claim", user.Roles)
	}
}

func TestPKCE(t *testing.T) {
	t.Parallel()

	idp := oidctest.New(t)
	auth, _ := newAuth(t, idp)

	cookie, q := start(t, auth, "/")
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q", got)
	}

	idp.Approve(q.Get("state"), q.Get("nonce"))
	if _, _, err := auth.Complete(context.Background(),
		callback(cookie, "code=code-"+q.Get("state")+"&state="+url.QueryEscape(q.Get("state")))); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	sum := sha256.Sum256([]byte(idp.LastVerifier))
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != q.Get("code_challenge") {
		t.Errorf("verifier hashes to %s, challenge was %s", got, q.Get("code_challenge"))
	}
}

func TestCallbackRejects(t *testing.T) {
	t.Parallel()

	idp := oidctest.New(t)
	auth, _ := newAuth(t, idp)

	cookie, q := start(t, auth, "/")
	idp.Approve(q.Get("state"), q.Get("nonce"))
	good := "code=code-" + q.Get("state") + "&state=" + url.QueryEscape(q.Get("state"))

	tampered := *cookie
	tampered.Value = cookie.Value[:len(cookie.Value)-2] + "XY"

	tests := map[string]*http.Request{
		"no flow cookie":  callback(nil, good),
		"wrong state":     callback(cookie, "code=abc&state=attacker"),
		"no state":        callback(cookie, "code=abc"),
		"tampered cookie": callback(&tampered, good),
	}

	for name, r := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := auth.Complete(context.Background(), r); !errors.Is(err, ErrFlow) {
				t.Errorf("err = %v, want ErrFlow", err)
			}
		})
	}
}

func TestCallbackRejectsReplayedNonce(t *testing.T) {
	t.Parallel()

	idp := oidctest.New(t)
	auth, _ := newAuth(t, idp)

	cookie, q := start(t, auth, "/")
	idp.Approve(q.Get("state"), q.Get("nonce"))
	idp.ForceNonce = "a-different-login"

	_, _, err := auth.Complete(context.Background(),
		callback(cookie, "code=code-"+q.Get("state")+"&state="+url.QueryEscape(q.Get("state"))))
	if err == nil {
		t.Fatal("accepted a token from a different login")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Errorf("err = %v, want it to name the nonce", err)
	}
}

// Login must not become an open redirect.
func TestNextStaysOnSite(t *testing.T) {
	t.Parallel()

	idp := oidctest.New(t)
	auth, _ := newAuth(t, idp)

	for _, hostile := range []string{
		"https://evil.example.com/",
		"//evil.example.com/",
		`/\evil.example.com`,
		"http://evil.example.com",
	} {
		if _, target := login(t, auth, idp, hostile); target != "/" {
			t.Errorf("next %q survived as %q", hostile, target)
		}
	}

	if _, target := login(t, auth, idp, "/setup"); target != "/setup" {
		t.Errorf("same-site next rewritten to %q", target)
	}
}

// Providers encode roles as a list or a space-separated string.
func TestRolesClaimShapes(t *testing.T) {
	t.Parallel()

	for name, shape := range map[string]any{
		"list":   []string{"a", "b"},
		"string": "a b",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			idp := oidctest.New(t)
			idp.Roles = shape
			auth, codec := newAuth(t, idp)

			session, _ := login(t, auth, idp, "/")
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.AddCookie(session)

			user, err := codec.Open(r)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if len(user.Roles) != 2 || user.Roles[0] != "a" || user.Roles[1] != "b" {
				t.Errorf("roles = %v, want [a b]", user.Roles)
			}
		})
	}
}

func TestLogoutURL(t *testing.T) {
	t.Parallel()

	idp := oidctest.New(t)
	auth, _ := newAuth(t, idp)

	target := auth.LogoutURL("https://gruff.example.com/")
	if !strings.HasPrefix(target, idp.Issuer+"/logout") {
		t.Fatalf("LogoutURL = %q", target)
	}

	q, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if q.Query().Get("client_id") != idp.ClientID {
		t.Error("logout URL does not identify the client")
	}
	if q.Query().Get("post_logout_redirect_uri") != "https://gruff.example.com/" {
		t.Error("logout URL does not carry the redirect")
	}
}
