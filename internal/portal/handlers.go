package portal

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
	"unicode"

	"github.com/shutthegoatup/gruff/internal/config"
)

// profileView is a profile as one particular caller may see it.
type profileView struct {
	config.Profile
	Permitted bool
}

func (p *Portal) handleProfiles(w http.ResponseWriter, r *http.Request) {
	id := p.identify(r)

	views := make([]profileView, 0, len(p.cfg.Profiles))
	granted := 0
	for _, profile := range p.cfg.Profiles {
		permitted := profile.AllowedFor(id.Roles)
		if permitted {
			granted++
		}
		views = append(views, profileView{Profile: profile, Permitted: permitted})
	}

	p.render(w, r, "profiles.html", struct {
		page
		Profiles     []profileView
		GrantedCount int
	}{p.page(id), views, granted})
}

func (p *Portal) handleProfile(w http.ResponseWriter, r *http.Request) {
	id := p.identify(r)
	profile, ok := p.authorize(w, r, id)
	if !ok {
		return
	}

	p.render(w, r, "rules.html", struct {
		page
		Profile config.Profile
	}{p.page(id), profile})
}

func (p *Portal) handleIssued(w http.ResponseWriter, r *http.Request) {
	id := p.identify(r)

	p.render(w, r, "issued.html", struct {
		page
		Sessions []Session
	}{p.page(id), p.sessions.For(id.Username)})
}

func (p *Portal) handleIssue(w http.ResponseWriter, r *http.Request) {
	id := p.identify(r)
	if id.Username == "" {
		p.log.WarnContext(r.Context(), "issue request with no authenticated user")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// The username is interpolated into the .ovpn body, which is rendered with
	// text/template and so is not escaped, and into the certificate subject.
	// Neither is a place for control characters.
	if !printableUsername(id.Username) {
		p.log.WarnContext(r.Context(), "rejected username containing control characters",
			"user", strconv.Quote(id.Username))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	profile, ok := p.authorize(w, r, id)
	if !ok {
		return
	}

	creds, err := p.ca.Issue(id.Username, profile.Name, time.Duration(profile.Duration))
	if err != nil {
		p.log.ErrorContext(r.Context(), "issue certificate", "user", id.Username, "profile", profile.Name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	p.sessions.Add(Session{
		User:      id.Username,
		Profile:   profile.Name,
		Serial:    creds.Serial,
		ClientIP:  clientIP(r),
		IssuedAt:  time.Now(),
		ExpiresAt: creds.NotAfter,
	})
	p.log.InfoContext(r.Context(), "issued certificate",
		"user", id.Username, "profile", profile.Name,
		"serial", creds.Serial, "expires", creds.NotAfter)

	filename := fmt.Sprintf("%s-%s.ovpn", profile.Name, creds.NotAfter.UTC().Format("20060102T150405Z"))
	w.Header().Set("Content-Type", "application/x-openvpn-profile")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Cache-Control", "no-store")

	data := struct {
		Session struct {
			User        string
			Profile     string
			Duration    string
			ExpiresOn   string
			Certificate string
			PrivateKey  string
			IssuingCA   string
		}
	}{}
	data.Session.User = id.Username
	data.Session.Profile = profile.Name
	data.Session.Duration = profile.Duration.String()
	data.Session.ExpiresOn = creds.NotAfter.UTC().Format(time.RFC3339)
	data.Session.Certificate = creds.Certificate
	data.Session.PrivateKey = creds.PrivateKey
	data.Session.IssuingCA = creds.IssuingCA

	// The response is already committed by the time a template error could
	// surface, so this can only be logged, not reported to the client.
	if err := p.cfg.ProfileTemplate().Execute(w, data); err != nil {
		p.log.ErrorContext(r.Context(), "render profile template", "user", id.Username, "error", err)
	}
}

// authorize resolves the {profile} path value and checks the caller may use it.
// An unknown profile and a forbidden one are reported identically so that the
// portal does not disclose which profiles exist.
func (p *Portal) authorize(w http.ResponseWriter, r *http.Request, id identity) (config.Profile, bool) {
	name := r.PathValue("profile")

	profile, err := p.cfg.Profile(name)
	if err != nil {
		if !errors.Is(err, config.ErrNoProfile) {
			p.log.ErrorContext(r.Context(), "look up profile", "profile", name, "error", err)
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return config.Profile{}, false
	}

	if !profile.AllowedFor(id.Roles) {
		p.log.WarnContext(r.Context(), "denied profile access",
			"user", id.Username, "profile", name, "roles", id.Roles)
		http.Error(w, "forbidden", http.StatusForbidden)
		return config.Profile{}, false
	}
	return profile, true
}

// printableUsername rejects control characters and unbounded input before the
// name reaches a certificate subject or an .ovpn body.
func printableUsername(user string) bool {
	if len(user) > 255 {
		return false
	}
	for _, r := range user {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
