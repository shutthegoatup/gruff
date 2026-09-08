// Package oidcauth runs the OpenID Connect authorization code flow.
//
// State, PKCE verifier and nonce travel in a short-lived encrypted cookie
// rather than server memory, so a login begun on one replica finishes on
// another.
package oidcauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/shutthegoatup/gruff/internal/authsession"
	"github.com/shutthegoatup/gruff/internal/config"
)

// The in-flight login, alive only between the redirect out and the callback.
// __Host- requires Secure; see authsession.CookieName.
const (
	flowCookie         = "__Host-gruff-flow"
	insecureFlowCookie = "gruff-flow"
)

const flowLifetime = 10 * time.Minute

// ErrFlow means the callback did not match a login this browser started.
var ErrFlow = errors.New("no matching login in progress")

// Authenticator performs the code flow and mints portal sessions.
type Authenticator struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    oauth2.Config
	sessions *authsession.Codec
	cfg      *config.Auth
	secure   bool
}

// flow is the state a login carries across the redirect.
type flow struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"r,omitempty"`
	Expires  int64  `json:"e"`
}

// New discovers the provider and builds an authenticator.
func New(ctx context.Context, cfg *config.Auth, sessions *authsession.Codec) (*Authenticator, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover issuer %s: %w", cfg.Issuer, err)
	}

	return &Authenticator{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.Secret(),
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.OIDCScopes(),
		},
		sessions: sessions,
		cfg:      cfg,
		secure:   !cfg.InsecureCookies,
	}, nil
}

// Start begins a login, returning the provider URL to redirect the browser to
// and the cookie that remembers this attempt.
func (a *Authenticator) Start(next string) (string, *http.Cookie, error) {
	state, err := randomString()
	if err != nil {
		return "", nil, err
	}
	nonce, err := randomString()
	if err != nil {
		return "", nil, err
	}
	verifier, err := randomString()
	if err != nil {
		return "", nil, err
	}

	f := flow{
		State:    state,
		Nonce:    nonce,
		Verifier: verifier,
		Next:     safeNext(next),
		Expires:  time.Now().Add(flowLifetime).Unix(),
	}
	cookie, err := a.sealFlow(f)
	if err != nil {
		return "", nil, err
	}

	challenge := sha256.Sum256([]byte(verifier))
	authURL := a.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:])),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	return authURL, cookie, nil
}

// Complete handles the provider's callback: it checks the request matches a
// login this browser started, exchanges the code, verifies the ID token and
// returns the session cookie to set.
func (a *Authenticator) Complete(ctx context.Context, r *http.Request) (*http.Cookie, string, error) {
	f, err := a.openFlow(r)
	if err != nil {
		return nil, "", err
	}

	// Compare before doing any work: this is the CSRF check on the callback.
	if state := r.URL.Query().Get("state"); state == "" || state != f.State {
		return nil, "", ErrFlow
	}
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		return nil, "", fmt.Errorf("provider refused the login: %s", errParam)
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, "", errors.New("callback carried no authorization code")
	}

	token, err := a.oauth.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", f.Verifier))
	if err != nil {
		return nil, "", fmt.Errorf("exchange code: %w", err)
	}

	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, "", errors.New("token response carried no id_token")
	}
	idToken, err := a.verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, "", fmt.Errorf("verify id_token: %w", err)
	}
	if idToken.Nonce != f.Nonce {
		return nil, "", errors.New("id_token nonce does not match the login")
	}

	user, err := a.identity(idToken)
	if err != nil {
		return nil, "", err
	}
	user.Expires = time.Now().Add(a.cfg.SessionDuration())
	// Never outlive the token that vouched for it.
	if !idToken.Expiry.IsZero() && idToken.Expiry.Before(user.Expires) {
		user.Expires = idToken.Expiry
	}

	cookie, err := a.sessions.Seal(user)
	if err != nil {
		return nil, "", err
	}
	return cookie, f.Next, nil
}

// identity pulls the username and roles out of the verified ID token.
func (a *Authenticator) identity(idToken *oidc.IDToken) (authsession.User, error) {
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return authsession.User{}, fmt.Errorf("read claims: %w", err)
	}

	username := stringClaim(claims, a.cfg.UsernameClaim)
	if username == "" {
		username = stringClaim(claims, "email")
	}
	if username == "" {
		username = idToken.Subject
	}

	return authsession.User{
		Username: username,
		Fullname: stringClaim(claims, "name"),
		Roles:    stringsClaim(claims, a.cfg.RolesClaim),
	}, nil
}

// LogoutURL is the provider's end-session endpoint if it advertises one, so
// signing out of Gruff can also sign out of the identity provider.
func (a *Authenticator) LogoutURL(redirect string) string {
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := a.provider.Claims(&meta); err != nil || meta.EndSession == "" {
		return ""
	}

	u, err := url.Parse(meta.EndSession)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("client_id", a.cfg.ClientID)
	if redirect != "" {
		q.Set("post_logout_redirect_uri", redirect)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// flowName is the cookie name for the in-flight login.
func (a *Authenticator) flowName() string {
	if a.secure {
		return flowCookie
	}
	return insecureFlowCookie
}

// ClearFlow removes an in-flight login cookie.
func (a *Authenticator) ClearFlow() *http.Cookie {
	return &http.Cookie{
		Name: a.flowName(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	}
}

func (a *Authenticator) sealFlow(f flow) (*http.Cookie, error) {
	payload, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("encode flow: %w", err)
	}
	// Reuse the session codec's key rather than introducing a second one; the
	// flow is a different payload under the same authenticated encryption.
	sealed, err := a.sessions.SealRaw(payload)
	if err != nil {
		return nil, err
	}

	return &http.Cookie{
		Name:     a.flowName(),
		Value:    sealed,
		Path:     "/",
		MaxAge:   int(flowLifetime.Seconds()),
		HttpOnly: true,
		Secure:   a.secure,
		// Lax, not Strict: the provider redirects the browser back to us, and
		// Strict would withhold the cookie on that cross-site navigation.
		SameSite: http.SameSiteLaxMode,
	}, nil
}

func (a *Authenticator) openFlow(r *http.Request) (flow, error) {
	cookie, err := r.Cookie(a.flowName())
	if err != nil {
		return flow{}, ErrFlow
	}
	payload, err := a.sessions.OpenRaw(cookie.Value)
	if err != nil {
		return flow{}, ErrFlow
	}

	var f flow
	if err := json.Unmarshal(payload, &f); err != nil {
		return flow{}, ErrFlow
	}
	if time.Now().Unix() > f.Expires {
		return flow{}, ErrFlow
	}
	return f, nil
}

// safeNext keeps a post-login redirect on this site. An absolute URL, or
// anything protocol-relative, would turn login into an open redirect.
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	if strings.Contains(next, "\\") {
		return "/"
	}
	return next
}

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func stringClaim(claims map[string]any, key string) string {
	if key == "" {
		return ""
	}
	s, _ := claims[key].(string)
	return s
}

// stringsClaim reads a roles claim, which providers variously encode as a list
// or as a single space-separated string.
func stringsClaim(claims map[string]any, key string) []string {
	if key == "" {
		return nil
	}
	switch v := claims[key].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	case string:
		return strings.Fields(v)
	default:
		return nil
	}
}
