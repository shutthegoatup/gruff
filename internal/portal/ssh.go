package portal

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/shutthegoatup/gruff/internal/config"
	"github.com/shutthegoatup/gruff/internal/sshca"
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

	p.sessions.Add(Session{
		User:      id.Username,
		Profile:   profile.Name,
		Kind:      KindSSH,
		Serial:    fmt.Sprintf("%d", creds.Serial),
		ClientIP:  clientIP(r),
		IssuedAt:  time.Now(),
		ExpiresAt: creds.NotAfter,
	})
	p.log.InfoContext(r.Context(), "issued ssh certificate",
		"user", id.Username, "profile", profile.Name,
		"serial", creds.Serial, "principals", creds.Principals, "expires", creds.NotAfter)

	name := "gruff-" + profile.Name
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name+".tar.gz"))
	w.Header().Set("Cache-Control", "no-store")

	// A tarball rather than loose files: it is the only delivery that carries
	// the 0600 the private key needs through to the user's disk.
	if err := writeSSHBundle(w, name, profile, creds); err != nil {
		p.log.ErrorContext(r.Context(), "write ssh bundle", "user", id.Username, "error", err)
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
		p.log.WarnContext(r.Context(), "denied ssh profile access",
			"user", id.Username, "profile", name, "roles", id.Roles)
		http.Error(w, "forbidden", http.StatusForbidden)
		return config.SSHProfile{}, false
	}
	return profile, true
}

// writeSSHBundle streams a gzipped tar holding the key, the certificate and an
// ssh_config fragment that wires them together.
func writeSSHBundle(w io.Writer, name string, profile config.SSHProfile, creds sshca.Credentials) error {
	gz := gzip.NewWriter(w)
	defer gz.Close()

	tw := tar.NewWriter(gz)
	defer tw.Close()

	files := []struct {
		name string
		mode int64
		body string
	}{
		{name + "/id_ed25519", 0o600, creds.PrivateKey},
		{name + "/id_ed25519-cert.pub", 0o644, creds.Certificate + "\n"},
		{name + "/config", 0o644, sshConfigFragment(name, profile, creds)},
		{name + "/README", 0o644, sshReadme(name, profile, creds)},
	}

	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name:    f.name,
			Mode:    f.mode,
			Size:    int64(len(f.body)),
			ModTime: time.Now(),
		}); err != nil {
			return err
		}
		if _, err := io.WriteString(tw, f.body); err != nil {
			return err
		}
	}
	return nil
}

func sshConfigFragment(name string, profile config.SSHProfile, creds sshca.Credentials) string {
	var b strings.Builder
	hosts := profile.Hosts
	if len(hosts) == 0 {
		hosts = []string{"*"}
	}

	fmt.Fprintf(&b, "# Gruff: %s, expires %s\n", profile.Name, creds.NotAfter.Format(time.RFC3339))
	fmt.Fprintf(&b, "Host %s\n", strings.Join(hosts, " "))
	fmt.Fprintf(&b, "    IdentityFile ~/.ssh/%s/id_ed25519\n", name)
	fmt.Fprintf(&b, "    CertificateFile ~/.ssh/%s/id_ed25519-cert.pub\n", name)
	b.WriteString("    IdentitiesOnly yes\n")
	return b.String()
}

func sshReadme(name string, profile config.SSHProfile, creds sshca.Credentials) string {
	var b strings.Builder

	fmt.Fprintf(&b, "%s\n\n", profile.Description)
	fmt.Fprintf(&b, "Certificate %d, valid until %s.\n", creds.Serial, creds.NotAfter.Format(time.RFC3339))
	fmt.Fprintf(&b, "Valid for login as: %s\n\n", strings.Join(creds.Principals, ", "))

	b.WriteString("Install:\n\n")
	fmt.Fprintf(&b, "    tar -xzf %s.tar.gz -C ~/.ssh/\n", name)
	fmt.Fprintf(&b, "    cat ~/.ssh/%s/config >> ~/.ssh/config\n\n", name)

	b.WriteString("Then connect as usual:\n\n")
	fmt.Fprintf(&b, "    ssh %s@<host>\n\n", creds.Principals[0])

	b.WriteString("The key expires on its own. Nothing needs revoking, and Gruff keeps\n")
	b.WriteString("no copy of it.\n")
	return b.String()
}
