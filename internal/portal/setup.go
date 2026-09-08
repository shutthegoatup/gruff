package portal

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/shutthegoatup/gruff/internal/config"
)

// handleSetup renders the server-side configuration an operator needs in order
// to trust Gruff: what to put in sshd_config, and what the OpenVPN server needs.
//
// This is the half of the job that is not certificate issuance. It is shown
// rather than assumed so that a deployment outside the bundled Helm chart -
// a plain host, a VM, a different orchestrator - has everything it needs.
func (p *Portal) handleSetup(w http.ResponseWriter, r *http.Request) {
	id := p.identify(r)

	data := struct {
		page
		SSHCAPublicKey  string
		SSHFingerprint  string
		SSHDConfig      string
		PrincipalsFiles []principalsFile
		HasSSH          bool

		VPNCACertificate string
		OpenVPNConfig    string
		HasVPN           bool
	}{page: p.page(id)}

	if p.sshCA != nil && len(p.cfg.SSHProfiles) > 0 {
		data.HasSSH = true
		data.SSHCAPublicKey = p.sshCA.PublicKey()
		data.SSHFingerprint = p.sshCA.Fingerprint()
		data.SSHDConfig = sshdConfig()
		data.PrincipalsFiles = principalsFiles(p.cfg.SSHProfiles)
	}

	if p.ca != nil && len(p.cfg.Profiles) > 0 {
		data.HasVPN = true
		data.VPNCACertificate = strings.TrimSpace(string(p.ca.CertificatePEM()))
		data.OpenVPNConfig = openvpnConfig(p.cfg)
	}

	p.render(w, r, "setup.html", data)
}

type principalsFile struct {
	Path    string
	Content string
}

// sshdConfig is the snippet that makes a host trust Gruff's CA.
func sshdConfig() string {
	return strings.Join([]string{
		"# Trust certificates signed by Gruff.",
		"TrustedUserCAKeys /etc/ssh/gruff_ca.pub",
		"",
		"# Only let a certificate log in as a principal listed for that login.",
		"AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u",
		"",
		"# Certificates are the only credential; nothing long-lived is enrolled.",
		"PasswordAuthentication no",
		"AuthenticationMethods publickey",
	}, "\n")
}

// principalsFiles maps each principal to the AuthorizedPrincipalsFile that must
// exist on the host for a login of that name to be permitted.
func principalsFiles(profiles []config.SSHProfile) []principalsFile {
	seen := map[string]bool{}
	for _, p := range profiles {
		for _, principal := range p.Principals {
			seen[principal] = true
		}
	}

	// Sorted so the page does not reshuffle between requests.
	principals := slices.Sorted(maps.Keys(seen))

	files := make([]principalsFile, 0, len(principals))
	for _, principal := range principals {
		files = append(files, principalsFile{
			Path:    "/etc/ssh/auth_principals/" + principal,
			Content: principal,
		})
	}
	return files
}

// openvpnConfig is the server-side directives that pair with the profiles Gruff
// issues: where the ccd files land, and that only known profiles may connect.
func openvpnConfig(cfg *config.Config) string {
	var b strings.Builder

	b.WriteString("ca /etc/openvpn/gruff-ca.pem\n")
	b.WriteString("\n")
	b.WriteString("# Gruff writes one file per profile here; ccd-exclusive refuses any\n")
	b.WriteString("# client whose certificate does not match one of them.\n")

	dir := cfg.ConfigdirPath
	if dir == "" {
		dir = "/var/lib/gruff/profiles"
	}
	fmt.Fprintf(&b, "client-config-dir %s\n", dir)
	b.WriteString("ccd-exclusive\n")
	b.WriteString("\n")
	b.WriteString("# Firewall rules are applied per connection from the same directory.\n")
	b.WriteString("script-security 2\n")
	fmt.Fprintf(&b, "client-connect %s/rules/connect.sh\n", dir)

	return b.String()
}
