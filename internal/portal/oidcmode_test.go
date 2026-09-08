package portal

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shutthegoatup/gruff/internal/authsession"
	"github.com/shutthegoatup/gruff/internal/config"
	"github.com/shutthegoatup/gruff/internal/oidcauth"
	"github.com/shutthegoatup/gruff/internal/oidcauth/oidctest"
	"github.com/shutthegoatup/gruff/internal/pki"
	"github.com/shutthegoatup/gruff/internal/sshca"
)

// newOIDCPortal builds a portal in oidc mode against a live test provider.
func newOIDCPortal(t *testing.T) (http.Handler, *oidctest.Provider) {
	t.Helper()

	idp := oidctest.New(t)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "session.key")
	key, err := authsession.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey(): %v", err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatalf("write session key: %v", err)
	}

	confPath := filepath.Join(dir, "conf.yaml")
	conf := testConfig + `
auth:
  mode: oidc
  issuer: ` + idp.Issuer + `
  client-id: gruff
  client-secret: shh
  redirect-url: http://gruff.example.com/auth/callback
  roles-claim: groups
  insecure-cookies: true
  session-key-file: ` + keyPath + "\n"
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(confPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	codec, err := authsession.NewCodec(cfg.Auth.SessionKey(), false)
	if err != nil {
		t.Fatalf("NewCodec(): %v", err)
	}
	auth, err := oidcauth.New(context.Background(), &cfg.Auth, codec)
	if err != nil {
		t.Fatalf("oidcauth.New(): %v", err)
	}

	ca, err := pki.Generate("Test Org")
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	sshCA, err := sshca.Generate()
	if err != nil {
		t.Fatalf("generate SSH CA: %v", err)
	}

	p, err := New(cfg, slog.New(slog.DiscardHandler), Options{
		CA: ca, SSHCA: sshCA, OIDC: auth, SessionCodec: codec,
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return p.Handler(), idp
}

// signIn drives the whole flow against the handler and returns the session
// cookie, exactly as a browser following the redirects would end up holding.
func signIn(t *testing.T, h http.Handler, idp *oidctest.Provider) *http.Cookie {
	t.Helper()

	// 1. Begin: the portal hands back a flow cookie and the provider URL.
	start := httptest.NewRecorder()
	h.ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/auth/login?next=%2Fssh", nil))
	if start.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d, want 303", start.Code)
	}
	flowCookie := cookieFrom(t, start.Result().Cookies(), "gruff-flow")

	// 2. The provider approves and redirects back with a code.
	authURL, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse provider URL: %v", err)
	}
	// Do not follow: the redirect points at the configured redirect_uri, a
	// host that does not exist. We want the Location, not to chase it.
	client := idp.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := client.Get(authURL.String())
	if err != nil {
		t.Fatalf("provider authorize: %v", err)
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatalf("provider did not redirect back; status %d", resp.StatusCode)
	}
	back, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse callback URL: %v", err)
	}
	if back.Query().Get("code") == "" {
		t.Fatalf("callback URL carries no code: %s", location)
	}

	// 3. The callback, carrying the flow cookie the browser kept.
	cb := httptest.NewRequest(http.MethodGet, "/auth/callback?"+back.RawQuery, nil)
	cb.AddCookie(flowCookie)

	done := httptest.NewRecorder()
	h.ServeHTTP(done, cb)
	if done.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d, want 303; body: %s", done.Code, done.Body)
	}
	if got := done.Header().Get("Location"); got != "/ssh" {
		t.Errorf("post-login redirect = %q, want /ssh", got)
	}
	return cookieFrom(t, done.Result().Cookies(), "gruff")
}

func cookieFrom(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()

	for _, c := range cookies {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	t.Fatalf("no %q cookie among %v", name, cookies)
	return nil
}

// Without a session, a page request is bounced to the provider rather than
// served with the zero identity.
func TestOIDCRedirectsAnonymous(t *testing.T) {
	t.Parallel()

	h, _ := newOIDCPortal(t)

	for _, path := range []string{"/", "/ssh", "/issued", "/setup", "/profile/livedata"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))

		if w.Code != http.StatusSeeOther {
			t.Errorf("GET %s status = %d, want 303", path, w.Code)
			continue
		}
		if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/auth/login?next=") {
			t.Errorf("GET %s redirected to %q, want the login route", path, loc)
		}
	}
}

// A POST cannot be bounced through a redirect without losing its body, so it
// is refused outright rather than silently doing nothing.
func TestOIDCRefusesAnonymousPost(t *testing.T) {
	t.Parallel()

	h, _ := newOIDCPortal(t)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/profile/livedata/issue", nil))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if strings.Contains(w.Body.String(), "BEGIN") {
		t.Error("an anonymous POST was served key material")
	}
}

// Health and static assets must stay reachable, or probes fail and the login
// page loads unstyled.
func TestOIDCLeavesProbesOpen(t *testing.T) {
	t.Parallel()

	h, _ := newOIDCPortal(t)

	for _, path := range []string{"/healthz", "/static/portal.css"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", path, w.Code)
		}
	}
}

// The end-to-end path: sign in, then use the session to reach an authorized
// page and issue a credential with roles taken from the ID token.
func TestOIDCSignInGrantsAccess(t *testing.T) {
	t.Parallel()

	h, idp := newOIDCPortal(t)
	session := signIn(t, h, idp)

	page := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ssh", nil)
	req.AddCookie(session)
	h.ServeHTTP(page, req)

	if page.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", page.Code)
	}
	body := page.Body.String()
	if !strings.Contains(body, "Alice Mercer") {
		t.Error("the signed-in user is not shown")
	}
	if !strings.Contains(body, "/ssh/bastion/issue") {
		t.Error("a role from the ID token did not grant its profile")
	}

	// And the session actually authorizes issuance.
	issue := httptest.NewRecorder()
	post := httptest.NewRequest(http.MethodPost, "/ssh/bastion/issue", nil)
	post.AddCookie(session)
	h.ServeHTTP(issue, post)

	if issue.Code != http.StatusOK {
		t.Fatalf("issue status = %d, want 200; body: %s", issue.Code, issue.Body)
	}
	if !strings.Contains(issue.Body.String(), "issued to  alice.mercer") {
		t.Error("the credential is not attributed to the signed-in user")
	}
}

// Roles come from the token, so a user without them is denied even though they
// are signed in.
func TestOIDCDeniesUngrantedProfile(t *testing.T) {
	t.Parallel()

	h, idp := newOIDCPortal(t)
	idp.Roles = []string{"some-other-group"}

	session := signIn(t, h, idp)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ssh/bastion/issue", nil)
	req.AddCookie(session)
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Error("a user without the role was served key material")
	}
}

// Logout is offered only where it works, and it genuinely clears the session.
func TestOIDCLogout(t *testing.T) {
	t.Parallel()

	h, idp := newOIDCPortal(t)
	session := signIn(t, h, idp)

	page := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(session)
	h.ServeHTTP(page, req)
	if !strings.Contains(page.Body.String(), "/auth/logout") {
		t.Error("no log-out control in oidc mode, where it does work")
	}

	out := httptest.NewRecorder()
	logout := httptest.NewRequest(http.MethodGet, "/auth/logout", nil)
	logout.AddCookie(session)
	h.ServeHTTP(out, logout)

	if out.Code != http.StatusSeeOther {
		t.Fatalf("logout status = %d, want 303", out.Code)
	}
	if loc := out.Header().Get("Location"); !strings.HasPrefix(loc, idp.Issuer+"/logout") {
		t.Errorf("logout redirect = %q, want the provider's end-session endpoint", loc)
	}

	var cleared bool
	for _, c := range out.Result().Cookies() {
		if c.Name == "gruff" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout did not clear the session cookie")
	}
}

// In proxy mode the auth routes must not exist: there is no session for them
// to act on, and mounting them would be misleading.
func TestProxyModeNoAuthRoutes(t *testing.T) {
	t.Parallel()

	h := newTestPortal(t)

	for _, path := range []string{"/auth/login", "/auth/callback", "/auth/logout"} {
		w := request(t, h, http.MethodGet, path, "alice", "vpn-livedata")
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404 in proxy mode", path, w.Code)
		}
	}
}
