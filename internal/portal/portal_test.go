package portal

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shutthegoatup/gruff/internal/config"
	"github.com/shutthegoatup/gruff/internal/pki"
	"github.com/shutthegoatup/gruff/internal/sshca"
)

const testConfig = `
banner: Test Portal
profiles:
  - name: livedata
    description: Live Data
    max-session: 2h
    roles: [vpn-livedata]
    routes:
      - 192.168.1.0/24
    rules:
      - dest: 192.168.1.0/24
        port: 53
        protocol: tcp
        action: ACCEPT
  - name: secret
    description: Secret Network
    max-session: 1h
    roles: [vpn-secret]
    routes:
      - 10.9.9.0/24
ssh-profiles:
  - name: bastion
    description: Bastion Hosts
    max-session: 1h
    roles: [ssh-bastion]
    principals: [deploy, ubuntu]
    hosts: ["bastion.example.com"]
  - name: dbadmin
    description: Database Admin
    max-session: 30m
    roles: [ssh-dbadmin]
    principals: [postgres]
template: |
  # profile {{ .Session.Profile }} for {{ .Session.User }}
  <ca>
  {{ .Session.IssuingCA }}</ca>
  <cert>
  {{ .Session.Certificate }}</cert>
  <key>
  {{ .Session.PrivateKey }}</key>
`

func newTestPortal(t *testing.T) http.Handler {
	t.Helper()

	path := filepath.Join(t.TempDir(), "conf.yaml")
	if err := os.WriteFile(path, []byte(testConfig), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	ca, err := pki.Generate("Test Org")
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	sshCA, err := sshca.Generate()
	if err != nil {
		t.Fatalf("generate SSH CA: %v", err)
	}

	p, err := New(cfg, slog.New(slog.DiscardHandler), Options{CA: ca, SSHCA: sshCA})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return p.Handler()
}

// request issues a request as a user holding roles.
func request(t *testing.T, h http.Handler, method, target, user, roles string) *httptest.ResponseRecorder {
	t.Helper()
	return serve(h, newRequest(method, target, user, roles))
}

func newRequest(method, target, user, roles string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	if user != "" {
		r.Header.Set("X-Auth-Username", user)
		r.Header.Set("X-Auth-Fullname", user)
	}
	if roles != "" {
		r.Header.Set("X-Auth-Roles", roles)
	}
	return r
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// The headline regression: a user without the profile's role could previously
// download a working certificate for it.
func TestIssueDeniesAUserWithoutTheRole(t *testing.T) {
	t.Parallel()

	h := newTestPortal(t)
	denied := []struct{ name, roles string }{
		{"no roles", ""},
		{"unrelated role", "vpn-other"},
		{"the other profile's role", "vpn-secret"},
		{"many unrelated roles", "a,b,c,d,e,f,g"},
		{"role is a prefix", "vpn-live"},
	}

	for _, tt := range denied {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := request(t, h, http.MethodPost, "/profile/livedata/issue", "mallory", tt.roles)
			if w.Code != http.StatusForbidden {
				t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
			}
			if strings.Contains(w.Body.String(), "BEGIN") {
				t.Error("a denied request was served key material")
			}
		})
	}
}

func TestIssueServesAProfileToAnAuthorisedUser(t *testing.T) {
	t.Parallel()

	w := request(t, newTestPortal(t), http.MethodPost, "/profile/livedata/issue", "alice", "vpn-livedata")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}

	body := w.Body.String()
	for _, want := range []string{"BEGIN CERTIFICATE", "BEGIN PRIVATE KEY", "profile livedata for alice"} {
		if !strings.Contains(body, want) {
			t.Errorf("profile is missing %q", want)
		}
	}

	if got := w.Header().Get("Content-Type"); got != "application/x-openvpn-profile" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := w.Header().Get("Content-Disposition"); !strings.Contains(got, "attachment") {
		t.Errorf("Content-Disposition = %q, want an attachment", got)
	}
	// A response carrying a private key must not be cached.
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestIssueRequiresAnAuthenticatedUser(t *testing.T) {
	t.Parallel()

	// Roles without a username means the proxy did not authenticate anyone.
	w := request(t, newTestPortal(t), http.MethodPost, "/profile/livedata/issue", "", "vpn-livedata")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// Issuance changes state, so it must not be reachable by a link, a prefetch or
// a crawler. It was a GET before.
func TestIssueRejectsGET(t *testing.T) {
	t.Parallel()

	w := request(t, newTestPortal(t), http.MethodGet, "/profile/livedata/issue", "alice", "vpn-livedata")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestIssueRejectsACrossOriginPost(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodPost, "/profile/livedata/issue", nil)
	r.Header.Set("X-Auth-Username", "alice")
	r.Header.Set("X-Auth-Roles", "vpn-livedata")
	r.Header.Set("Sec-Fetch-Site", "cross-site")

	w := httptest.NewRecorder()
	newTestPortal(t).ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d for a cross-origin POST", w.Code, http.StatusForbidden)
	}
	if strings.Contains(w.Body.String(), "BEGIN") {
		t.Error("a cross-origin request was served key material")
	}
}

// The detail page previously had no authorization check at all, disclosing
// every profile's routes, rules and required roles to any caller.
func TestProfileDetailRequiresTheRole(t *testing.T) {
	t.Parallel()

	h := newTestPortal(t)

	w := request(t, h, http.MethodGet, "/profile/secret", "mallory", "vpn-livedata")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if strings.Contains(w.Body.String(), "10.9.9.0") {
		t.Error("an unauthorised caller was shown the profile's routes")
	}

	if w := request(t, h, http.MethodGet, "/profile/secret", "alice", "vpn-secret"); w.Code != http.StatusOK {
		t.Errorf("authorised status = %d, want 200", w.Code)
	}
}

// An unknown profile and a forbidden one must be indistinguishable, so the
// portal does not disclose which profiles exist.
func TestUnknownProfileLooksLikeAForbiddenOne(t *testing.T) {
	t.Parallel()

	h := newTestPortal(t)
	unknown := request(t, h, http.MethodGet, "/profile/does-not-exist", "alice", "vpn-livedata")
	forbidden := request(t, h, http.MethodGet, "/profile/secret", "alice", "vpn-livedata")

	if unknown.Code != forbidden.Code {
		t.Errorf("unknown profile = %d, forbidden profile = %d; want identical", unknown.Code, forbidden.Code)
	}
	if unknown.Body.String() != forbidden.Body.String() {
		t.Error("unknown and forbidden profiles produce distinguishable responses")
	}
}

// The index lists every profile, but marks as permitted only those the caller
// actually holds, and discloses rules only for those.
func TestProfileIndexMarksOnlyPermittedProfiles(t *testing.T) {
	t.Parallel()

	w := request(t, newTestPortal(t), http.MethodGet, "/", "alice", "vpn-livedata")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "/profile/livedata/issue") {
		t.Error("the permitted profile has no download form")
	}
	if strings.Contains(body, "/profile/secret/issue") {
		t.Error("an unpermitted profile was given a download form")
	}
	if strings.Contains(body, "10.9.9.0") {
		t.Error("an unpermitted profile's routes were disclosed on the index")
	}
}

// /issued previously showed every user's name and client IP to every caller.
func TestIssuedIsScopedToTheRequestingUser(t *testing.T) {
	t.Parallel()

	h := newTestPortal(t)

	if w := request(t, h, http.MethodPost, "/profile/livedata/issue", "alice", "vpn-livedata"); w.Code != http.StatusOK {
		t.Fatalf("issue for alice: status = %d", w.Code)
	}

	w := request(t, h, http.MethodGet, "/issued", "bob", "vpn-livedata")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if strings.Contains(w.Body.String(), "livedata") {
		t.Error("bob was shown alice's session")
	}

	if w := request(t, h, http.MethodGet, "/issued", "alice", "vpn-livedata"); !strings.Contains(w.Body.String(), "livedata") {
		t.Error("alice was not shown her own session")
	}
}

func TestSecurityHeaders(t *testing.T) {
	t.Parallel()

	w := request(t, newTestPortal(t), http.MethodGet, "/", "alice", "vpn-livedata")

	want := map[string]string{
		"X-Content-Type-Options":     "nosniff",
		"Referrer-Policy":            "no-referrer",
		"Cross-Origin-Opener-Policy": "same-origin",
	}
	for header, value := range want {
		if got := w.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("Content-Security-Policy = %q, want a default-src 'none' baseline", csp)
	}
}

// The pages must render from the embedded FS, with no working-directory
// dependency: the binary is deployed without the web/ tree beside it.
// Not parallel: t.Chdir cannot be combined with t.Parallel.
func TestStaticAssetsAreServedFromTheBinary(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Chdir(t.TempDir())

	w := request(t, newTestPortal(t), http.MethodGet, "/static/portal.css", "alice", "vpn-livedata")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 while running outside %s", w.Code, cwd)
	}
	if b, _ := io.ReadAll(w.Body); len(b) == 0 {
		t.Error("stylesheet is empty")
	}
}
