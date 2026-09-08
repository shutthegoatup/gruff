// Package portal serves the web interface that issues OpenVPN profiles.
//
// The portal performs no authentication of its own. It is designed to sit
// behind an SSO reverse proxy that authenticates the user and injects identity
// headers, and it must never be reachable directly: anything that can connect
// to it can assert its own identity and roles.
package portal

import (
	"bytes"
	"cmp"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"

	"github.com/shutthegoatup/gruff/internal/config"
	"github.com/shutthegoatup/gruff/internal/pki"
	"github.com/shutthegoatup/gruff/internal/sshca"
	"github.com/shutthegoatup/gruff/web"
)

const layout = "layout.html"

// pages are the page templates, each composed with the shared layout.
var pages = []string{"profiles.html", "rules.html", "issued.html", "ssh.html", "setup.html"}

// Portal holds everything the handlers need. Nothing here is package state, so
// a request can never observe or corrupt another request's view of it.
type Portal struct {
	cfg       *config.Config
	ca        *pki.CA
	sshCA     *sshca.CA
	log       *slog.Logger
	sessions  SessionStore
	templates map[string]*template.Template
}

// New builds a portal from validated configuration and its loaded authorities.
// Either CA may be nil when no profile of that kind is configured.
func New(cfg *config.Config, ca *pki.CA, sshCA *sshca.CA, log *slog.Logger) (*Portal, error) {
	templates, err := parseTemplates(web.Files)
	if err != nil {
		return nil, err
	}
	return &Portal{cfg: cfg, ca: ca, sshCA: sshCA, log: log, templates: templates}, nil
}

// parseTemplates builds one template set per page. Each page defines its own
// "body", so they cannot share a set without overwriting one another.
func parseTemplates(fsys fs.FS) (map[string]*template.Template, error) {
	templates := make(map[string]*template.Template, len(pages))
	for _, name := range pages {
		t, err := template.ParseFS(fsys, path.Join("template", layout), path.Join("template", name))
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}
		templates[name] = t
	}
	return templates, nil
}

// identity is the caller as asserted by the upstream SSO proxy.
type identity struct {
	Username string
	Fullname string
	Roles    []string
}

func (p *Portal) identify(r *http.Request) identity {
	return identity{
		Username: r.Header.Get(p.cfg.UsernameHeader),
		Fullname: r.Header.Get(p.cfg.FullnameHeader),
		Roles:    config.Roles(r.Header.Get(p.cfg.RolesHeader)),
	}
}

// render executes a page into a buffer before writing it, so that a template
// failure yields a clean 500 rather than a half-rendered page under a 200.
func (p *Portal) render(w http.ResponseWriter, r *http.Request, page string, data any) {
	t, ok := p.templates[page]
	if !ok {
		p.log.ErrorContext(r.Context(), "unknown template", "template", page)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, layout, data); err != nil {
		p.log.ErrorContext(r.Context(), "render template", "template", page, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// page is the data every template needs for the surrounding chrome.
type page struct {
	Title     string
	Brand     string
	Username  string
	Initials  string
	LogoutURL string
	HelpURL   string
}

func (p *Portal) page(id identity) page {
	name := cmp.Or(id.Fullname, id.Username)
	return page{
		Title:     p.cfg.Banner,
		Brand:     p.cfg.Banner,
		Username:  name,
		Initials:  initials(name),
		LogoutURL: p.cfg.LogoutURL,
		HelpURL:   p.cfg.HelpURL,
	}
}

// initials renders an avatar label from a display name, at most two letters.
func initials(name string) string {
	var out []rune
	for _, field := range strings.Fields(name) {
		out = append(out, []rune(field)[0])
		if len(out) == 2 {
			break
		}
	}
	return string(out)
}
