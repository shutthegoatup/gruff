package portal

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/shutthegoatup/gruff/internal/authsession"
	"github.com/shutthegoatup/gruff/internal/config"
	"github.com/shutthegoatup/gruff/internal/oidcauth"
)

// identity is the caller, however they were authenticated. Everything
// downstream works from this and does not care which mode produced it.
type identity struct {
	Username string
	Fullname string
	Roles    []string
}

// identify resolves the caller.
//
// In proxy mode this reads headers an upstream is trusted to have set. In OIDC
// mode it opens the session cookie Gruff itself issued; a caller with no valid
// session resolves to the zero identity, which grants nothing, and the
// requireSession middleware sends them to log in.
func (p *Portal) identify(r *http.Request) identity {
	if p.oidc == nil {
		return identity{
			Username: r.Header.Get(p.cfg.UsernameHeader),
			Fullname: r.Header.Get(p.cfg.FullnameHeader),
			Roles:    config.Roles(r.Header.Get(p.cfg.RolesHeader)),
		}
	}

	user, err := p.sessionCodec.Open(r)
	if err != nil {
		return identity{}
	}
	return identity{Username: user.Username, Fullname: user.Fullname, Roles: user.Roles}
}

// requireSession redirects an unauthenticated caller to the provider. It only
// applies in OIDC mode: in proxy mode the proxy has already decided, and Gruff
// has nowhere to send anyone.
func (p *Portal) requireSession(next http.Handler) http.Handler {
	if p.oidc == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := p.sessionCodec.Open(r); err != nil {
			// Only bounce a navigation. A POST would lose its body across the
			// redirect, so it gets a plain 403 to retry after signing in.
			if r.Method != http.MethodGet {
				http.Error(w, "not signed in", http.StatusForbidden)
				return
			}
			http.Redirect(w, r, "/auth/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (p *Portal) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Already signed in: nothing to do.
	if _, err := p.sessionCodec.Open(r); err == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	authURL, cookie, err := p.oidc.Start(r.URL.Query().Get("next"))
	if err != nil {
		p.log.ErrorContext(r.Context(), "start login", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, cookie)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func (p *Portal) handleCallback(w http.ResponseWriter, r *http.Request) {
	session, next, err := p.oidc.Complete(r.Context(), r)
	http.SetCookie(w, p.oidc.ClearFlow())

	if err != nil {
		// A mismatched or absent flow is the ordinary case for a stale tab or
		// a forged callback, and is not worth an error page beyond this.
		level := "error"
		if errors.Is(err, oidcauth.ErrFlow) {
			level = "warn"
		}
		p.logCallbackFailure(r, level, err)
		http.Error(w, "sign-in failed", http.StatusForbidden)
		return
	}

	http.SetCookie(w, session)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (p *Portal) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, p.sessionCodec.Clear())

	// Hand off to the provider so the sign-out is not only local; without this
	// the next login would complete silently and look like it never happened.
	if target := p.oidc.LogoutURL(p.cfg.LogoutURL); target != "" {
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (p *Portal) logCallbackFailure(r *http.Request, level string, err error) {
	if level == "warn" {
		p.log.WarnContext(r.Context(), "sign-in did not match a login in progress", "error", err)
		return
	}
	p.log.ErrorContext(r.Context(), "sign-in failed", "error", err)
}

// canLogout reports whether the portal can actually end a session, which
// decides whether the log-out control is shown at all.
func (p *Portal) canLogout() bool {
	// In OIDC mode Gruff owns the session and can always clear it. In proxy
	// mode it can only link to whatever the operator configured.
	return p.oidc != nil || p.cfg.LogoutURL != ""
}

// logoutHref is where the log-out control points.
func (p *Portal) logoutHref() string {
	if p.oidc != nil {
		return "/auth/logout"
	}
	return p.cfg.LogoutURL
}

var _ = authsession.User{}
