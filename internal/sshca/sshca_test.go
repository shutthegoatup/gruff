package sshca

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestIssueProducesAVerifiableCertificate(t *testing.T) {
	t.Parallel()

	ca := generateCA(t)
	creds, err := ca.Issue("alice", "bastion", []string{"deploy", "ubuntu"}, time.Hour, []string{"permit-pty"})
	if err != nil {
		t.Fatalf("Issue(): %v", err)
	}

	cert := parseCert(t, creds.Certificate)

	// The certificate must actually verify against the CA a host would trust,
	// for one of the principals it names.
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return string(auth.Marshal()) == string(caPublicKey(t, ca).Marshal())
		},
	}
	if err := checker.CheckCert("deploy", cert); err != nil {
		t.Fatalf("certificate does not verify for principal deploy: %v", err)
	}

	if cert.CertType != ssh.UserCert {
		t.Errorf("CertType = %d, want a user certificate", cert.CertType)
	}
	if cert.KeyId != "alice@bastion" {
		t.Errorf("KeyId = %q, want alice@bastion", cert.KeyId)
	}
	if _, ok := cert.Permissions.Extensions["permit-pty"]; !ok {
		t.Error("permit-pty extension is missing")
	}
	if _, ok := cert.Permissions.Extensions["permit-port-forwarding"]; ok {
		t.Error("port forwarding was granted but not asked for")
	}
}

// A certificate must not be usable as a login it was not issued for.
func TestCertificateRejectsAnUnlistedPrincipal(t *testing.T) {
	t.Parallel()

	ca := generateCA(t)
	creds, err := ca.Issue("alice", "bastion", []string{"deploy"}, time.Hour, nil)
	if err != nil {
		t.Fatalf("Issue(): %v", err)
	}

	cert := parseCert(t, creds.Certificate)
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return string(auth.Marshal()) == string(caPublicKey(t, ca).Marshal())
		},
	}

	if err := checker.CheckCert("root", cert); err == nil {
		t.Error("certificate verified for a principal it does not name")
	}
}

func TestIssueHonoursTheRequestedDuration(t *testing.T) {
	t.Parallel()

	const d = 30 * time.Minute
	creds, err := generateCA(t).Issue("bob", "bastion", []string{"deploy"}, d, nil)
	if err != nil {
		t.Fatalf("Issue(): %v", err)
	}
	cert := parseCert(t, creds.Certificate)

	notBefore := time.Unix(int64(cert.ValidAfter), 0)
	notAfter := time.Unix(int64(cert.ValidBefore), 0)

	// A minute of backdating absorbs clock skew, so the window is d + 1m.
	if got := notAfter.Sub(notBefore); got < d || got > d+2*time.Minute {
		t.Errorf("validity window = %s, want about %s", got, d)
	}
	if !creds.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter = %s, want the certificate's %s", creds.NotAfter, notAfter)
	}
	if time.Until(notAfter) <= 0 {
		t.Error("issued certificate is already expired")
	}
}

func TestIssueGeneratesFreshMaterialEachTime(t *testing.T) {
	t.Parallel()

	ca := generateCA(t)
	first, err := ca.Issue("alice", "bastion", []string{"deploy"}, time.Hour, nil)
	if err != nil {
		t.Fatalf("Issue(): %v", err)
	}
	second, err := ca.Issue("alice", "bastion", []string{"deploy"}, time.Hour, nil)
	if err != nil {
		t.Fatalf("Issue(): %v", err)
	}

	if first.Serial == second.Serial {
		t.Error("two certificates share a serial")
	}
	if first.PrivateKey == second.PrivateKey {
		t.Error("two certificates share a private key")
	}
	if !strings.Contains(first.PrivateKey, "OPENSSH PRIVATE KEY") {
		t.Errorf("private key is not in OpenSSH format:\n%s", first.PrivateKey)
	}
	// The issued key must be the one the certificate is bound to.
	if _, err := ssh.ParsePrivateKey([]byte(first.PrivateKey)); err != nil {
		t.Errorf("issued private key does not parse: %v", err)
	}
}

func TestIssueRequiresPrincipals(t *testing.T) {
	t.Parallel()

	if _, err := generateCA(t).Issue("alice", "bastion", nil, time.Hour, nil); err == nil {
		t.Error("Issue() accepted a profile with no principals")
	}
}

func TestPublicKeyIsAnAuthorizedKeysLine(t *testing.T) {
	t.Parallel()

	ca := generateCA(t)
	line := ca.PublicKey()

	if !strings.HasPrefix(line, "ssh-ed25519 ") {
		t.Errorf("PublicKey() = %q, want an ssh-ed25519 line", line)
	}
	if strings.Contains(line, "\n") {
		t.Error("PublicKey() should be a single line")
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err != nil {
		t.Errorf("PublicKey() does not parse as an authorized key: %v", err)
	}
	if !strings.HasPrefix(ca.Fingerprint(), "SHA256:") {
		t.Errorf("Fingerprint() = %q", ca.Fingerprint())
	}
}

func TestWriteToProtectsThePrivateKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := generateCA(t).WriteTo(dir); err != nil {
		t.Fatalf("WriteTo(): %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "ssh", "ca"))
	if err != nil {
		t.Fatalf("stat CA key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("CA key mode = %#o, want 0600", perm)
	}
}

// A CA written out must load back and issue, so a generated one can be promoted
// to ssh-ca-private-file.
func TestLoadRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	original := generateCA(t)
	if err := original.WriteTo(dir); err != nil {
		t.Fatalf("WriteTo(): %v", err)
	}

	loaded, err := Load(filepath.Join(dir, "ssh", "ca"))
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if loaded.PublicKey() != original.PublicKey() {
		t.Error("loaded CA has a different public key")
	}
	if _, err := loaded.Issue("alice", "bastion", []string{"deploy"}, time.Hour, nil); err != nil {
		t.Errorf("Issue() after Load(): %v", err)
	}
}

func TestLoadRejectsGarbage(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "not-a-key")
	if err := os.WriteFile(path, []byte("nonsense"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Error("Load() accepted a file that is not a private key")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("Load() accepted a missing file")
	}
}

func generateCA(t *testing.T) *CA {
	t.Helper()

	ca, err := Generate()
	if err != nil {
		t.Fatalf("Generate(): %v", err)
	}
	return ca
}

func caPublicKey(t *testing.T, ca *CA) ssh.PublicKey {
	t.Helper()

	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ca.PublicKey()))
	if err != nil {
		t.Fatalf("parse CA public key: %v", err)
	}
	return key
}

func parseCert(t *testing.T, line string) *ssh.Certificate {
	t.Helper()

	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed %T, want a certificate", key)
	}
	return cert
}
