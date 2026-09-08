package portal

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/shutthegoatup/gruff/internal/config"
)

// sshProfileView is an SSH profile as one particular caller may see it.
type sshProfileView struct {
	config.SSHProfile
	Permitted bool
}

func (p *Portal) handleSSHProfiles(w http.ResponseWriter, r *http.Request) {
	id := p.identify(r)

	views := make([]sshProfileView, 0, len(p.cfg.SSHProfiles))
	granted := 0
	for _, profile := range p.cfg.SSHProfiles {
		permitted := profile.AllowedFor(id.Roles)
		if permitted {
			granted++
		}
		views = append(views, sshProfileView{SSHProfile: profile, Permitted: permitted})
	}

	p.render(w, r, "ssh.html", struct {
		page
		Profiles     []sshProfileView
		GrantedCount int
	}{p.page(id), views, granted})
}

func (p *Portal) handleSSHIssue(w http.ResponseWriter, r *http.Request) {
	id := p.identify(r)
	if id.Username == "" {
		p.log.WarnContext(r.Context(), "ssh issue request with no authenticated user")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !printableUsername(id.Username) {
		p.log.WarnContext(r.Context(), "rejected username containing control characters")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	profile, ok := p.authorizeSSH(w, r, id)
	if !ok {
		return
	}
	if p.rateLimited(w, r, id.Username) {
		return
	}
	if p.sshCA == nil {
		p.log.ErrorContext(r.Context(), "ssh profile configured without an SSH CA", "profile", profile.Name)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	creds, err := p.sshCA.Issue(
		id.Username, profile.Name, profile.Principals,
		time.Duration(profile.Duration), profile.GrantedExtensions(),
	)
	if err != nil {
		p.log.ErrorContext(r.Context(), "issue ssh certificate", "user", id.Username, "profile", profile.Name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := p.sessions.Add(r.Context(), Session{
		User:      id.Username,
		Profile:   profile.Name,
		Kind:      KindSSH,
		Serial:    fmt.Sprintf("%d", creds.Serial),
		ClientIP:  clientIP(r),
		IssuedAt:  time.Now(),
		ExpiresAt: creds.NotAfter,
	}); err != nil {
		p.log.ErrorContext(r.Context(), "record issued ssh session", "user", id.Username, "error", err)
	}
	p.metrics.inc(metricIssued, "kind", string(KindSSH), "profile", profile.Name)
	p.log.InfoContext(r.Context(), "issued ssh certificate",
		"user", id.Username, "profile", profile.Name,
		"serial", creds.Serial, "principals", creds.Principals, "expires", creds.NotAfter)

	w.Header().Set("Content-Type", "application/x-shellscript")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", "gruff-"+profile.Name+".sh"))
	w.Header().Set("Cache-Control", "no-store")

	if err := writeSSHInstaller(w, profile, id.Username, creds); err != nil {
		p.log.ErrorContext(r.Context(), "write ssh installer", "user", id.Username, "error", err)
	}
}

func (p *Portal) authorizeSSH(w http.ResponseWriter, r *http.Request, id identity) (config.SSHProfile, bool) {
	name := r.PathValue("profile")

	profile, err := p.cfg.SSHProfile(name)
	if err != nil {
		if !errors.Is(err, config.ErrNoProfile) {
			p.log.ErrorContext(r.Context(), "look up ssh profile", "profile", name, "error", err)
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return config.SSHProfile{}, false
	}
	if !profile.AllowedFor(id.Roles) {
		p.metrics.inc(metricDenied, "kind", string(KindSSH))
		p.log.WarnContext(r.Context(), "denied ssh profile access",
			"user", id.Username, "profile", name, "roles", id.Roles)
		http.Error(w, "forbidden", http.StatusForbidden)
		return config.SSHProfile{}, false
	}
	return profile, true
}
