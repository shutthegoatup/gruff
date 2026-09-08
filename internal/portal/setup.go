package portal

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/shutthegoatup/gruff/internal/config"
)

// handleSetup renders what a host needs in order to trust Gruff, so a
// deployment outside the bundled chart is not left guessing. Public material
// only.
func (p *Portal) handleSetup(w http.ResponseWriter, r *http.Request) {
	id := p.identify(r)

	data := struct {
		page
		SSHCAPublicKey  string
		SSHFingerprint  string
		SSHDConfig      string
		KnownHosts      string
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
		data.SSHDConfig = sshdConfig(p.cfg)
		data.KnownHosts = p.sshCA.KnownHostsLine(hostPatterns(p.cfg.SSHProfiles))
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

// hostPatterns is every host any SSH profile names, for the client-side
// cert-authority line.
func hostPatterns(profiles []config.SSHProfile) []string {
	seen := map[string]bool{}
	for _, p := range profiles {
		for _, h := range p.Hosts {
			seen[h] = true
		}
	}
	return slices.Sorted(maps.Keys(seen))
}

// sshdConfig is the snippet that makes a host trust Gruff's CA.
//
// Each file it names has to be on the host before sshd reloads. RevokedKeys is
// the trap: if the file is missing sshd still starts and sshd -t still passes,
// but every public key is then refused, so a host whose only method is
// publickey locks everyone out with nothing in the config test to show for it.
// The snippet therefore says where each file comes from.
func sshdConfig(cfg *config.Config) string {
	lines := []string{
		"# Trust user certificates signed by Gruff. The key is above; copy it here.",
		"TrustedUserCAKeys /etc/ssh/gruff_ca.pub",
		"",
		"# Present this host's own certificate, so clients stop being asked to",
		"# confirm a fingerprint:  gruff sign-host -host " + exampleHost(cfg),
		"HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub",
		"",
		"# Certificates Gruff has revoked. A missing file here does not stop sshd",
		"# starting - it silently refuses every public key. Put an empty one in",
		"# place first if you have nothing to revoke yet.",
	}

	// The SSH host is not the machine Gruff runs on, so unlike the OpenVPN
	// directives this is a copy rather than a shared directory.
	if cfg.ConfigdirEnabled && cfg.ConfigdirPath != "" {
		lines = append(lines,
			"# Gruff rewrites "+cfg.ConfigdirPath+"/krl hourly and on every revocation;",
			"# ship that file to each host.")
	} else {
		lines = append(lines,
			"# Enable configdir-path on the portal to have Gruff write one.")
	}

	lines = append(lines,
		"RevokedKeys /etc/ssh/gruff_krl",
		"",
		"# Only let a certificate log in as a principal listed for that login.",
		"AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u",
		"",
		"# Certificates are the only credential; nothing long-lived is enrolled.",
		"PasswordAuthentication no",
		"AuthenticationMethods publickey",
	)
	return strings.Join(lines, "\n")
}

// exampleHost picks a name from the configured profiles so the sign-host
// command reads as something to run rather than something to adapt.
func exampleHost(cfg *config.Config) string {
	for _, p := range cfg.SSHProfiles {
		if len(p.Hosts) > 0 {
			return p.Hosts[0]
		}
	}
	return "<this-host>"
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

	dir := cfg.ConfigdirPath
	if dir == "" {
		dir = "/var/lib/gruff/profiles"
	}

	b.WriteString("# Routes come from this hook, not client-config-dir: the certificate's\n")
	b.WriteString("# common name is the user, so a ccd file cannot select a profile. The\n")
	b.WriteString("# hook reads the profile from the certificate and refuses anything else.\n")
	b.WriteString("script-security 2\n")
	fmt.Fprintf(&b, "client-connect %s/rules/connect.sh\n", dir)
	b.WriteString("\n")
	b.WriteString("# Revoked certificates. Gruff rewrites this hourly and on revocation.\n")
	fmt.Fprintf(&b, "crl-verify %s/crl.pem\n", dir)

	return b.String()
}
