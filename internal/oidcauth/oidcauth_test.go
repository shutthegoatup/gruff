package oidcauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/shutthegoatup/gruff/internal/authsession"
	"github.com/shutthegoatup/gruff/internal/config"
)

// provider is a minimal OpenID Connect provider: enough discovery, JWKS and
// token endpoint to drive a real code flow through the real library.
type provider struct {
	*httptest.Server
	key      *rsa.PrivateKey
	issuer   string
	clientID string

	// lastVerifier records the PKCE verifier the exchange presented.
	lastVerifier string
	// nonce is stamped into the issued ID token.
	nonce string
	// roles is the claim value handed back.
	roles any
}

func newProvider(t *testing.T) *provider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	p := &provider{key: key, clientID: "gruff", roles: []string{"vpn-livedata", "ssh-bastion"}}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                 p.issuer,
			"authorization_endpoint": p.issuer + "/authorize",
			"token_endpoint":         p.issuer + "/token",
			"jwks_uri":               p.issuer + "/jwks",
			"end_session_endpoint":   p.issuer + "/logout",
		})
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: p.key.Public(), KeyID: "test", Algorithm: "RS256", Use: "sig",
		}}})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		p.lastVerifier = r.Form.Get("code_verifier")

		writeJSON(w, map[string]any{
			"access_token": "access",
			"token_type":   "Bearer",
			"id_token":     p.idToken(t, p.nonce),
		})
	})

	p.Server = httptest.NewServer(mux)
	p.issuer = p.Server.URL
	t.Cleanup(p.Close)
	return p
}

func (p *provider) idToken(t *testing.T, nonce string) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	claims := map[string]any{
		"iss":                p.issuer,
		"aud":                p.clientID,
		"sub":                "alice-subject",
		"exp":                time.Now().Add(time.Hour).Unix(),
		"iat":                time.Now().Unix(),
		"nonce":              nonce,
		"preferred_username": "alice.mercer",
		"name":               "Alice Mercer",
		"groups":             p.roles,
	}

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}
	return raw
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func newAuth(t *testing.T, p *provider) (*Authenticator, *authsession.Codec) {
	t.Helper()

	key, err := authsession.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey(): %v", err)
	}
	codec, err := authsession.NewCodec(key, false)
	if err != nil {
		t.Fatalf("NewCodec(): %v", err)
	}

	cfg := &config.Auth{
		Mode:            config.AuthOIDC,
		Issuer:          p.issuer,
		ClientID:        p.clientID,
		ClientSecret:    "secret",
		RedirectURL:     "http://127.0.0.1/auth/callback",
		RolesClaim:      "groups",
		UsernameClaim:   "preferred_username",
		InsecureCookies: true,
	}

	auth, err := New(context.Background(), cfg, codec)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return auth, codec
}

// login drives a full flow and returns the session cookie and redirect target.
func login(t *testing.T, auth *Authenticator, p *provider, next string) (*http.Cookie, string) {
	t.Helper()

	authURL, flowCk, err := auth.Start(next)
	if err != nil {
		t.Fatalf("Start(): %v", err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	p.nonce = u.Query().Get("nonce")

	callback := httptest.NewRequest(http.MethodGet,
		"/auth/callback?code=abc&state="+url.QueryEscape(u.Query().Get("state")), nil)
	callback.AddCookie(flowCk)

	session, target, err := auth.Complete(context.Background(), callback)
	if err != nil {
		t.Fatalf("Complete(): %v", err)
	}
	return session, target
}

func TestFullFlowProducesASession(t *testing.T) {
	t.Parallel()

	p := newProvider(t)
	auth, codec := newAuth(t, p)

	session, target := login(t, auth, p, "/ssh")
	if target != "/ssh" {
		t.Errorf("redirect = %q, want /ssh", target)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(session)

	user, err := codec.Open(r)
	if err != nil {
		t.Fatalf("session does not open: %v", err)
	}
	if user.Username != "alice.mercer" {
		t.Errorf("Username = %q, want alice.mercer", user.Username)
	}
	if user.Fullname != "Alice Mercer" {
		t.Errorf("Fullname = %q", user.Fullname)
	}
	if len(user.Roles) != 2 || user.Roles[0] != "vpn-livedata" {
		t.Errorf("Roles = %v, want the groups claim", user.Roles)
	}
}

// PKCE: the verifier presented at the token endpoint must hash to the
// challenge sent on the authorize request.
func TestFlowUsesPKCE(t *testing.T) {
	t.Parallel()

	p := newProvider(t)
	auth, _ := newAuth(t, p)

	authURL, flowCk, err := auth.Start("/")
	if err != nil {
		t.Fatalf("Start(): %v", err)
	}
	u, _ := url.Parse(authURL)
	challenge := u.Query().Get("code_challenge")

	if u.Query().Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", u.Query().Get("code_challenge_method"))
	}
	if challenge == "" {
		t.Fatal("no code_challenge on the authorize request")
	}

	p.nonce = u.Query().Get("nonce")
	callback := httptest.NewRequest(http.MethodGet,
		"/auth/callback?code=abc&state="+url.QueryEscape(u.Query().Get("state")), nil)
	callback.AddCookie(flowCk)
	if _, _, err := auth.Complete(context.Background(), callback); err != nil {
		t.Fatalf("Complete(): %v", err)
	}

	sum := sha256.Sum256([]byte(p.lastVerifier))
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != challenge {
		t.Errorf("verifier does not hash to the challenge: %s vs %s", got, challenge)
	}
}

// The callback must not be usable without the cookie from the same browser
// that started the login, and the state must match.
func TestCallbackRejectsForgedRequests(t *testing.T) {
	t.Parallel()

	p := newProvider(t)
	auth, _ := newAuth(t, p)

	authURL, flowCk, err := auth.Start("/")
	if err != nil {
		t.Fatalf("Start(): %v", err)
	}
	u, _ := url.Parse(authURL)
	good := u.Query().Get("state")
	p.nonce = u.Query().Get("nonce")

	t.Run("no flow cookie", func(t *testing.T) {
		t.Parallel()
		r := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state="+good, nil)
		if _, _, err := auth.Complete(context.Background(), r); !errors.Is(err, ErrFlow) {
			t.Errorf("error = %v, want ErrFlow", err)
		}
	})

	t.Run("mismatched state", func(t *testing.T) {
		t.Parallel()
		r := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state=attacker", nil)
		r.AddCookie(flowCk)
		if _, _, err := auth.Complete(context.Background(), r); !errors.Is(err, ErrFlow) {
			t.Errorf("error = %v, want ErrFlow", err)
		}
	})

	t.Run("no state", func(t *testing.T) {
		t.Parallel()
		r := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc", nil)
		r.AddCookie(flowCk)
		if _, _, err := auth.Complete(context.Background(), r); !errors.Is(err, ErrFlow) {
			t.Errorf("error = %v, want ErrFlow", err)
		}
	})

	t.Run("tampered flow cookie", func(t *testing.T) {
		t.Parallel()
		bad := *flowCk
		bad.Value = flowCk.Value[:len(flowCk.Value)-2] + "XY"
		r := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state="+good, nil)
		r.AddCookie(&bad)
		if _, _, err := auth.Complete(context.Background(), r); !errors.Is(err, ErrFlow) {
			t.Errorf("error = %v, want ErrFlow", err)
		}
	})
}

// A token whose nonce does not match the login must be refused: this is the
// replay defence.
func TestCallbackRejectsAMismatchedNonce(t *testing.T) {
	t.Parallel()

	p := newProvider(t)
	auth, _ := newAuth(t, p)

	authURL, flowCk, err := auth.Start("/")
	if err != nil {
		t.Fatalf("Start(): %v", err)
	}
	u, _ := url.Parse(authURL)
	p.nonce = "a-different-login"

	r := httptest.NewRequest(http.MethodGet,
		"/auth/callback?code=abc&state="+url.QueryEscape(u.Query().Get("state")), nil)
	r.AddCookie(flowCk)

	_, _, err = auth.Complete(context.Background(), r)
	if err == nil {
		t.Fatal("accepted an id_token from a different login")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Errorf("error = %v, want it to mention the nonce", err)
	}
}

// The post-login redirect must stay on this site.
func TestNextIsConfinedToThisSite(t *testing.T) {
	t.Parallel()

	p := newProvider(t)
	auth, _ := newAuth(t, p)

	for _, hostile := range []string{
		"https://evil.example.com/",
		"//evil.example.com/",
		"/\\evil.example.com",
		"http://evil.example.com",
	} {
		_, target := login(t, auth, p, hostile)
		if target != "/" {
			t.Errorf("next %q survived as %q, want /", hostile, target)
		}
	}

	if _, target := login(t, auth, p, "/setup"); target != "/setup" {
		t.Errorf("a same-site next was rewritten to %q", target)
	}
}

// Providers encode roles either as a list or a space-separated string.
func TestRolesClaimShapes(t *testing.T) {
	t.Parallel()

	for name, shape := range map[string]any{
		"list":   []string{"a", "b"},
		"string": "a b",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := newProvider(t)
			p.roles = shape
			auth, codec := newAuth(t, p)

			session, _ := login(t, auth, p, "/")
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.AddCookie(session)

			user, err := codec.Open(r)
			if err != nil {
				t.Fatalf("open session: %v", err)
			}
			if len(user.Roles) != 2 || user.Roles[0] != "a" || user.Roles[1] != "b" {
				t.Errorf("Roles = %v, want [a b]", user.Roles)
			}
		})
	}
}

func TestLogoutURLUsesTheProvidersEndSession(t *testing.T) {
	t.Parallel()

	p := newProvider(t)
	auth, _ := newAuth(t, p)

	target := auth.LogoutURL("https://gruff.example.com/")
	if !strings.HasPrefix(target, p.issuer+"/logout") {
		t.Fatalf("LogoutURL = %q, want the provider's end_session_endpoint", target)
	}
	u, _ := url.Parse(target)
	if u.Query().Get("client_id") != p.clientID {
		t.Error("logout URL does not identify the client")
	}
	if u.Query().Get("post_logout_redirect_uri") != "https://gruff.example.com/" {
		t.Error("logout URL does not carry the redirect")
	}
}
