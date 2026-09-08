package portal

import (
	"io/fs"
	"net/http"

	"github.com/shutthegoatup/gruff/web"
)

// Handler builds the fully wrapped HTTP handler for the portal.
func (p *Portal) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", p.handleProfiles)
	mux.HandleFunc("GET /issued", p.handleIssued)
	mux.HandleFunc("GET /profile/{profile}", p.handleProfile)
	mux.HandleFunc("POST /profile/{profile}/issue", p.handleIssue)
	mux.HandleFunc("GET /healthz", p.handleHealth)

	static, err := fs.Sub(web.Files, "static")
	if err != nil {
		panic("web: static assets missing from embedded FS: " + err.Error())
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))

	// Ordering matters: CSRF protection must see the request before any
	// handler acts on it, and security headers must be set on every response
	// including those the CSRF layer rejects.
	return securityHeaders(http.NewCrossOriginProtection().Handler(mux))
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
