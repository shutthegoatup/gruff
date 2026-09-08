package portal

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/shutthegoatup/gruff/internal/config"
	"github.com/shutthegoatup/gruff/internal/sshca"
)

// Quoted at the point of use so the shell expands nothing between them.
const (
	keyDelim  = "GRUFF_KEY_EOF"
	certDelim = "GRUFF_CERT_EOF"
	confDelim = "GRUFF_CONF_EOF"
)

// writeSSHInstaller emits a self-contained POSIX shell script.
//
// A tarball leaves the user to fix the private key's mode by hand, which is the
// easiest part to get wrong. The script is idempotent, contacts nothing, and is
// plain text so it can be read before it is run.
func writeSSHInstaller(w io.Writer, profile config.SSHProfile, user string, creds sshca.Credentials) error {
	dir := "${HOME}/.ssh/gruff/" + profile.Name
	expires := creds.NotAfter.Format(time.RFC3339)

	var b strings.Builder

	b.WriteString("#!/bin/sh\n")
	b.WriteString("#\n")
	fmt.Fprintf(&b, "# Gruff SSH credential: %s\n", profile.Description)
	fmt.Fprintf(&b, "#   issued to  %s\n", user)
	fmt.Fprintf(&b, "#   logs in as %s\n", strings.Join(creds.Principals, ", "))
	fmt.Fprintf(&b, "#   expires    %s\n", expires)
	fmt.Fprintf(&b, "#   serial     %d\n", creds.Serial)
	b.WriteString("#\n")
	b.WriteString("# Installs a key and certificate under ~/.ssh/gruff and adds one Include\n")
	b.WriteString("# line to ~/.ssh/config. It downloads nothing and contacts nothing: every\n")
	b.WriteString("# byte it writes is below. Read it before running it.\n")
	b.WriteString("#\n")
	b.WriteString("# The credential expires on its own. Nothing needs revoking, and Gruff\n")
	b.WriteString("# keeps no copy of the private key.\n")
	b.WriteString("\n")
	b.WriteString("set -eu\n")
	b.WriteString("\n")
	fmt.Fprintf(&b, "DIR=\"%s\"\n", dir)
	b.WriteString("CONFIG=\"${HOME}/.ssh/config\"\n")
	b.WriteString("INCLUDE='Include ~/.ssh/gruff/*/config'\n")
	b.WriteString("\n")
	b.WriteString("umask 077\n")
	b.WriteString("mkdir -p \"$DIR\"\n")
	b.WriteString("\n")

	// Private key.
	fmt.Fprintf(&b, "cat > \"$DIR/id_ed25519\" <<'%s'\n", keyDelim)
	b.WriteString(creds.PrivateKey)
	if !strings.HasSuffix(creds.PrivateKey, "\n") {
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "%s\n", keyDelim)
	b.WriteString("chmod 600 \"$DIR/id_ed25519\"\n\n")

	// Certificate.
	fmt.Fprintf(&b, "cat > \"$DIR/id_ed25519-cert.pub\" <<'%s'\n", certDelim)
	b.WriteString(creds.Certificate)
	b.WriteString("\n")
	fmt.Fprintf(&b, "%s\n", certDelim)
	b.WriteString("chmod 644 \"$DIR/id_ed25519-cert.pub\"\n\n")

	// ssh_config fragment.
	fmt.Fprintf(&b, "cat > \"$DIR/config\" <<'%s'\n", confDelim)
	b.WriteString(sshConfigFragment(profile, expires))
	fmt.Fprintf(&b, "%s\n", confDelim)
	b.WriteString("chmod 644 \"$DIR/config\"\n\n")

	// Wire the fragment in, exactly once. Include has to precede the Host
	// blocks it should win against, since ssh_config takes the first value it
	// finds for any option.
	b.WriteString("if [ ! -f \"$CONFIG\" ]; then\n")
	b.WriteString("\tprintf '%s\\n' \"$INCLUDE\" > \"$CONFIG\"\n")
	b.WriteString("\tchmod 600 \"$CONFIG\"\n")
	b.WriteString("\techo \"created $CONFIG\"\n")
	b.WriteString("elif ! grep -qF \"$INCLUDE\" \"$CONFIG\"; then\n")
	b.WriteString("\ttmp=$(mktemp)\n")
	b.WriteString("\tprintf '%s\\n\\n' \"$INCLUDE\" > \"$tmp\"\n")
	b.WriteString("\tcat \"$CONFIG\" >> \"$tmp\"\n")
	// Copy rather than move, so the original file keeps its inode and mode.
	b.WriteString("\tcat \"$tmp\" > \"$CONFIG\"\n")
	b.WriteString("\trm -f \"$tmp\"\n")
	b.WriteString("\techo \"added Include to $CONFIG\"\n")
	b.WriteString("fi\n\n")

	b.WriteString("echo\n")
	fmt.Fprintf(&b, "echo \"Installed %s. Expires %s.\"\n", profile.Name, expires)
	b.WriteString("echo\n")
	b.WriteString("echo 'Connect with:'\n")
	for _, target := range connectExamples(profile, creds) {
		fmt.Fprintf(&b, "echo '    ssh %s'\n", target)
	}
	b.WriteString("echo\n")

	_, err := io.WriteString(w, b.String())
	return err
}

// sshConfigFragment binds the key and certificate to the profile's hosts.
func sshConfigFragment(profile config.SSHProfile, expires string) string {
	hosts := profile.Hosts
	if len(hosts) == 0 {
		// No hosts configured: match nothing implicitly, and say so, rather
		// than silently claiming every host the user ever connects to.
		hosts = []string{"# set hosts: on this profile to bind these automatically"}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Gruff: %s, expires %s\n", profile.Name, expires)

	if strings.HasPrefix(hosts[0], "#") {
		b.WriteString(hosts[0] + "\n")
		fmt.Fprintf(&b, "# Host your-host.example.com\n")
		fmt.Fprintf(&b, "#     IdentityFile ~/.ssh/gruff/%s/id_ed25519\n", profile.Name)
		fmt.Fprintf(&b, "#     CertificateFile ~/.ssh/gruff/%s/id_ed25519-cert.pub\n", profile.Name)
		b.WriteString("#     IdentitiesOnly yes\n")
		return b.String()
	}

	fmt.Fprintf(&b, "Host %s\n", strings.Join(hosts, " "))
	fmt.Fprintf(&b, "    IdentityFile ~/.ssh/gruff/%s/id_ed25519\n", profile.Name)
	fmt.Fprintf(&b, "    CertificateFile ~/.ssh/gruff/%s/id_ed25519-cert.pub\n", profile.Name)
	b.WriteString("    IdentitiesOnly yes\n")
	return b.String()
}

// connectExamples pairs each principal with a host so the script can print a
// command that will actually work.
func connectExamples(profile config.SSHProfile, creds sshca.Credentials) []string {
	host := "<host>"
	if len(profile.Hosts) > 0 {
		host = profile.Hosts[0]
	}

	out := make([]string, 0, len(creds.Principals))
	for _, principal := range creds.Principals {
		out = append(out, principal+"@"+host)
	}
	return out
}
