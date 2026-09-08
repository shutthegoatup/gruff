package portal

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/shutthegoatup/gruff/web"
)

// Handler builds the fully wrapped HTTP handler for the portal.
func (p *Portal) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", p.handleProfiles)
	mux.HandleFunc("GET /issued", p.handleIssued)
	mux.HandleFunc("GET /profile/{profile}", p.handleProfile)
	mux.HandleFunc("POST /profile/{profile}/issue", p.handleIssue)

	mux.HandleFunc("GET /ssh", p.handleSSHProfiles)
	mux.HandleFunc("POST /ssh/{profile}/issue", p.handleSSHIssue)

	mux.HandleFunc("GET /setup", p.handleSetup)
	mux.HandleFunc("GET /healthz", p.handleHealth)

	// Only mounted when Gruff owns the session; in proxy mode there is nothing
	// for these to do and they would be misleading.
	if p.oidc != nil {
		mux.HandleFunc("GET /auth/login", p.handleLogin)
		mux.HandleFunc("GET /auth/callback", p.handleCallback)
		mux.HandleFunc("POST /auth/logout", p.handleLogout)
		mux.HandleFunc("GET /auth/logout", p.handleLogout)
	}

	static, err := fs.Sub(web.Files, "static")
	if err != nil {
		panic("web: static assets missing from embedded FS: " + err.Error())
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))

	// Ordering matters, outermost first: security headers must be set on every
	// response, including those the layers below reject; CSRF protection must
	// see a request before any handler acts on it; and the session gate sits
	// innermost so the auth routes themselves stay reachable.
	return securityHeaders(http.NewCrossOriginProtection().Handler(p.gate(mux)))
}

// gate applies the session requirement to everything except the routes needed
// to establish a session in the first place, and the health probe.
func (p *Portal) gate(mux *http.ServeMux) http.Handler {
	if p.oidc == nil {
		return mux
	}

	guarded := p.requireSession(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/healthz",
			strings.HasPrefix(r.URL.Path, "/auth/"),
			strings.HasPrefix(r.URL.Path, "/static/"):
			mux.ServeHTTP(w, r)
		default:
			guarded.ServeHTTP(w, r)
		}
	})
}

func (p *Portal) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("ok\n"))
}

// securityHeaders applies a restrictive baseline to every response. The content
// security policy can be this strict because all styles and assets are served
// from the binary itself rather than a CDN.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; "+
				"form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}
