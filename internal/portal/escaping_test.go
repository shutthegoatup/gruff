package portal

import (
	"net/http"
	"strings"
	"testing"
)

// Identity comes from a trusted SSO proxy, but the portal renders it into HTML,
// so it is treated as untrusted at the point of rendering. These tests pin that
// html/template's contextual escaping is actually in force: a regression here
// would most likely be someone introducing template.HTML to "fix" some markup.
func TestIdentityIsEscapedInHTML(t *testing.T) {
	t.Parallel()

	payloads := []struct {
		name, value, mustNotContain string
	}{
		{"script tag", `<script>alert(1)</script>`, "<script>alert(1)</script>"},
		{"img onerror", `<img src=x onerror=alert(1)>`, "<img src=x"},
		{"attribute break", `" autofocus onfocus="alert(1)`, `onfocus="alert(1)`},
		{"closing tag", `</span><script>alert(1)</script>`, "<script>"},
	}

	for _, tt := range payloads {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newTestPortal(t)
			r := newRequest(http.MethodGet, "/", "alice", "vpn-livedata")
			r.Header.Set("X-Auth-Fullname", tt.value)

			w := serve(h, r)
			body := w.Body.String()

			if strings.Contains(body, tt.mustNotContain) {
				t.Errorf("payload rendered unescaped: %q appears in the response", tt.mustNotContain)
			}
			// The value should still be present, just inert.
			if !strings.Contains(body, "&lt;") && !strings.Contains(body, "&#34;") {
				t.Error("expected the payload to appear HTML-escaped")
			}
		})
	}
}

// A profile name reaches an href. html/template escapes URL contexts
// differently from text; make sure that path is exercised too.
func TestProfileNameIsEscapedInURLContext(t *testing.T) {
	t.Parallel()

	w := request(t, newTestPortal(t), http.MethodGet, "/", "alice", "vpn-livedata")
	body := w.Body.String()

	if strings.Contains(body, "javascript:") {
		t.Error("a javascript: URL survived rendering")
	}
	if !strings.Contains(body, `action="/profile/livedata/issue"`) {
		t.Error("expected the issue form action to render")
	}
}

// The .ovpn body is rendered with text/template, which does no escaping at all
// - correctly, since it is not HTML. That makes the username the one value
// worth constraining before it reaches the file.
func TestUsernameWithControlCharactersIsRejected(t *testing.T) {
	t.Parallel()

	h := newTestPortal(t)
	injected := "alice\npush \"route 10.0.0.0 255.0.0.0\""

	r := newRequest(http.MethodPost, "/profile/livedata/issue", injected, "vpn-livedata")
	w := serve(h, r)

	if w.Code == http.StatusOK {
		t.Fatalf("a username containing a newline was accepted; body:\n%s", w.Body)
	}
	if strings.Contains(w.Body.String(), "push \"route") {
		t.Error("injected OpenVPN directive reached the response")
	}
}
