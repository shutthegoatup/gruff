package sshca

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// hostKey generates a host keypair and returns its public half in
// authorized_keys form, plus the private key path.
func hostKey(t *testing.T) (string, string) {
	t.Helper()

	keygen := sshKeygen(t)
	path := filepath.Join(t.TempDir(), "ssh_host_ed25519_key")
	if out, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	pub, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	return string(pub), path
}

func TestSignHost(t *testing.T) {
	t.Parallel()

	ca := generateCA(t)
	pub, _ := hostKey(t)

	creds, err := ca.SignHost(pub, []string{"bastion.example.com", "10.0.0.5"}, time.Now())
	if err != nil {
		t.Fatalf("SignHost: %v", err)
	}
	cert := parseCert(t, creds.Certificate)

	if cert.CertType != ssh.HostCert {
		t.Errorf("CertType = %d, want a host certificate", cert.CertType)
	}
	if len(cert.ValidPrincipals) != 2 || cert.ValidPrincipals[0] != "bastion.example.com" {
		t.Errorf("ValidPrincipals = %v", cert.ValidPrincipals)
	}
	// Host certificates carry no permit-* extensions; those are a user concept.
	if len(cert.Permissions.Extensions) != 0 {
		t.Errorf("Extensions = %v, want none on a host certificate", cert.Permissions.Extensions)
	}
	if got := time.Unix(int64(cert.ValidBefore), 0).Sub(time.Unix(int64(cert.ValidAfter), 0)); got < HostCertValidity {
		t.Errorf("validity window = %s, want at least %s", got, HostCertValidity)
	}
}

func TestSignHostRejects(t *testing.T) {
	t.Parallel()

	ca := generateCA(t)
	pub, _ := hostKey(t)

	userCert, err := ca.Issue("alice", "bastion", []string{"deploy"}, time.Hour, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	tests := map[string]struct {
		key        string
		principals []string
	}{
		"no principals":         {pub, nil},
		"not a key":             {"not-a-key", []string{"host"}},
		"empty":                 {"", []string{"host"}},
		"already a certificate": {userCert.Certificate, []string{"host"}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ca.SignHost(tt.key, tt.principals, time.Now()); err == nil {
				t.Error("SignHost accepted invalid input")
			}
		})
	}
}

func TestKnownHostsLine(t *testing.T) {
	t.Parallel()

	ca := generateCA(t)

	line := ca.KnownHostsLine([]string{"*.example.com", "10.0.0.*"})
	if !strings.HasPrefix(line, "@cert-authority *.example.com,10.0.0.* ssh-ed25519 ") {
		t.Errorf("KnownHostsLine = %q", line)
	}
	if strings.Count(line, "\n") != 0 {
		t.Error("known_hosts entries are one line")
	}

	if !strings.HasPrefix(ca.KnownHostsLine(nil), "@cert-authority * ") {
		t.Errorf("no patterns should mean all hosts, got %q", ca.KnownHostsLine(nil))
	}
}

// The point of the feature: ssh connects without being asked to confirm a
// fingerprint, because the host certificate chains to a CA the client trusts.
func TestHostCertificateIsAcceptedByOpenSSH(t *testing.T) {
	t.Parallel()

	keygen := sshKeygen(t)
	ca := generateCA(t)
	pub, keyPath := hostKey(t)

	creds, err := ca.SignHost(pub, []string{"bastion.example.com"}, time.Now())
	if err != nil {
		t.Fatalf("SignHost: %v", err)
	}

	certPath := keyPath + "-cert.pub"
	if err := os.WriteFile(certPath, []byte(creds.Certificate+"\n"), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	out, err := exec.Command(keygen, "-L", "-f", certPath).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen rejected the host certificate: %v\n%s", err, out)
	}
	for _, want := range []string{"host certificate", "bastion.example.com"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("certificate listing missing %q:\n%s", want, out)
		}
	}
}
