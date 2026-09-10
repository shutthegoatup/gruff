package portal

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/shutthegoatup/gruff/internal/config"
	"github.com/shutthegoatup/gruff/internal/oidcauth"
)

// identity is the caller, however they were authenticated. Everything
// downstream works from this and does not care which mode produced it.
type identity struct {
	Username string
	Fullname string
	Roles    []string
	Admin    bool
}

// identify resolves the caller from the session cookie, or from proxy headers
// when Gruff is not the authenticator. No valid session yields the zero
// identity, which grants nothing.
func (p *Portal) identify(r *http.Request) identity {
	var id identity
	if p.oidc == nil {
		id = identity{
			Username: r.Header.Get(p.cfg.UsernameHeader),
			Fullname: r.Header.Get(p.cfg.FullnameHeader),
			Roles:    config.Roles(r.Header.Get(p.cfg.RolesHeader)),
		}
	} else {
		user, err := p.sessionCodec.Open(r)
		if err != nil {
			return identity{}
		}
		id = identity{
			Username: user.Username,
			Fullname: user.Fullname,
			Roles:    user.Roles,
		}
	}

	// Grant locally-assigned roles on top of whatever the provider supplied,
	// so an operator can profile access without controlling the SSO provider's
	// claims or the proxy's roles header.
	id.Roles = mergeRoles(id.Roles, p.cfg.Auth.LocalRoles[id.Username])
	id.Admin = p.cfg.IsAdmin(id.Roles)
	return id
}

// mergeRoles returns the de-duplicated union of the supplied role sets, in
// order of first appearance (provider roles first, then local roles).
func mergeRoles(provider, local []string) []string {
	shown := make(map[string]bool, len(provider)+len(local))
	out := make([]string, 0, len(provider)+len(local))
	for _, r := range provider {
		if !shown[r] {
			shown[r] = true
			out = append(out, r)
		}
	}
	for _, r := range local {
		if !shown[r] {
			shown[r] = true
			out = append(out, r)
		}
	}
	return out
}

// requireSession redirects an unauthenticated caller to the provider. In proxy
// mode the proxy has already decided and there is nowhere to send anyone.
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
		// A stale tab or a forged callback is ordinary; a verification failure
		// is not.
		p.metrics.inc(metricSignIn)
		if errors.Is(err, oidcauth.ErrFlow) {
			p.log.WarnContext(r.Context(), "sign-in did not match a login in progress")
		} else {
			p.log.ErrorContext(r.Context(), "sign-in failed", "error", err)
		}
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

// canLogout decides whether the control is shown at all: Gruff can end a
// session it owns, otherwise only link to whatever the operator configured.
func (p *Portal) canLogout() bool {
	return p.oidc != nil || p.cfg.LogoutURL != ""
}

func (p *Portal) logoutHref() string {
	if p.oidc != nil {
		return "/auth/logout"
	}
	return p.cfg.LogoutURL
}
