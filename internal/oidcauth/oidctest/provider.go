// Package oidctest provides a minimal OpenID Connect provider for tests.
//
// It implements just enough - discovery, JWKS, an auto-approving authorize
// endpoint and a token endpoint - to drive a real authorization code flow
// through the real client library, so tests exercise the actual verification
// path rather than a stand-in for it.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Provider is a running test identity provider.
type Provider struct {
	*httptest.Server

	// Issuer is the discovery URL, available once New returns.
	Issuer string
	// ClientID the provider expects; defaults to "gruff".
	ClientID string

	// Identity handed back in the ID token. Change before signing in.
	Username string
	Fullname string
	Roles    any

	key *rsa.PrivateKey

	mu sync.Mutex
	// nonces maps an issued code to the nonce of the login that produced it.
	nonces map[string]string
	// LastVerifier is the PKCE verifier presented at the token endpoint.
	LastVerifier string
	// ForceNonce, when set, is stamped into the ID token instead of the nonce
	// of the login that produced the code - for exercising replay rejection.
	ForceNonce string
	// TokenLifetime is how long the ID token is valid. Real providers default
	// to minutes; Keycloak ships five.
	TokenLifetime time.Duration
}

// New starts a provider and registers its shutdown with t.
func New(t *testing.T) *Provider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("oidctest: generate key: %v", err)
	}

	p := &Provider{
		ClientID:      "gruff",
		Username:      "alice.mercer",
		Fullname:      "Alice Mercer",
		Roles:         []string{"vpn-livedata", "ssh-bastion"},
		TokenLifetime: time.Hour,
		key:           key,
		nonces:        map[string]string{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/jwks", p.jwks)
	mux.HandleFunc("/authorize", p.authorize)
	mux.HandleFunc("/token", p.token)
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("signed out"))
	})

	p.Server = httptest.NewServer(mux)
	p.Issuer = p.Server.URL
	t.Cleanup(p.Close)
	return p
}

func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                 p.Issuer,
		"authorization_endpoint": p.Issuer + "/authorize",
		"token_endpoint":         p.Issuer + "/token",
		"jwks_uri":               p.Issuer + "/jwks",
		"end_session_endpoint":   p.Issuer + "/logout",
	})
}

func (p *Provider) jwks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: p.key.Public(), KeyID: "test", Algorithm: "RS256", Use: "sig",
	}}})
}

// authorize approves immediately and redirects back with a code, standing in
// for the user consenting at the provider.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	if state == "" {
		http.Error(w, "no state", http.StatusBadRequest)
		return
	}
	code := "code-" + state

	p.mu.Lock()
	p.nonces[code] = q.Get("nonce")
	p.mu.Unlock()

	back, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	rq := back.Query()
	rq.Set("code", code)
	rq.Set("state", state)
	back.RawQuery = rq.Encode()

	http.Redirect(w, r, back.String(), http.StatusSeeOther)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	p.mu.Lock()
	p.LastVerifier = r.Form.Get("code_verifier")
	nonce := p.nonces[r.Form.Get("code")]
	if p.ForceNonce != "" {
		nonce = p.ForceNonce
	}
	p.mu.Unlock()

	writeJSON(w, map[string]any{
		"access_token": "access",
		"token_type":   "Bearer",
		"id_token":     p.IDToken(nonce),
	})
}

// Approve registers a code for state without going through the authorize
// endpoint, for tests that drive Complete directly.
func (p *Provider) Approve(state, nonce string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nonces["code-"+state] = nonce
}

// IDToken signs an ID token carrying nonce and the configured identity.
func (p *Provider) IDToken(nonce string) string {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"),
	)
	if err != nil {
		panic("oidctest: new signer: " + err.Error())
	}

	raw, err := jwt.Signed(signer).Claims(map[string]any{
		"iss":                p.Issuer,
		"aud":                p.ClientID,
		"sub":                "subject-" + p.Username,
		"exp":                time.Now().Add(p.TokenLifetime).Unix(),
		"iat":                time.Now().Unix(),
		"nonce":              nonce,
		"preferred_username": p.Username,
		"name":               p.Fullname,
		"groups":             p.Roles,
	}).Serialize()
	if err != nil {
		panic("oidctest: sign id_token: " + err.Error())
	}
	return raw
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
