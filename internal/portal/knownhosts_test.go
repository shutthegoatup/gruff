package portal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The client half of host certificates: after installing, ssh trusts any host
// certificate this CA signed instead of asking about a fingerprint.
func TestInstallerAddsHostCertificateAuthority(t *testing.T) {
	t.Parallel()

	home := runInstaller(t, issueInstaller(t, "bastion", "ssh-bastion"))

	known, err := os.ReadFile(filepath.Join(home, ".ssh", "known_hosts"))
	if err != nil {
		t.Fatalf("known_hosts was not written: %v", err)
	}
	body := string(known)

	if !strings.HasPrefix(body, "@cert-authority ") {
		t.Errorf("known_hosts does not start with a cert-authority line:\n%s", body)
	}
	if !strings.Contains(body, "bastion.example.com") {
		t.Errorf("the authority is not scoped to the profile's hosts:\n%s", body)
	}
	if !strings.Contains(body, "ssh-ed25519 ") {
		t.Errorf("no CA key in the known_hosts line:\n%s", body)
	}
}

func TestInstallerHostAuthorityIsIdempotent(t *testing.T) {
	t.Parallel()

	script := issueInstaller(t, "bastion", "ssh-bastion")
	home := runInstaller(t, script)
	runInstallerIn(t, script, home)

	known, err := os.ReadFile(filepath.Join(home, ".ssh", "known_hosts"))
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	if got := strings.Count(string(known), "@cert-authority"); got != 1 {
		t.Errorf("authority appears %d times after two runs, want 1:\n%s", got, known)
	}
}
