package pki

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIssueProducesAVerifiableClientCertificate(t *testing.T) {
	t.Parallel()

	ca := generateCA(t)
	creds, err := ca.Issue("alice", "livedata", time.Hour)
	if err != nil {
		t.Fatalf("Issue(): %v", err)
	}

	cert := parseCert(t, creds.Certificate)

	// The certificate must chain to the issuing CA the profile embeds.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(creds.IssuingCA)) {
		t.Fatal("IssuingCA is not a usable PEM certificate")
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("issued certificate does not verify against its own CA: %v", err)
	}

	// The subject identifies the person, so a credential on the wire is
	// attributable. The previous implementation used the profile name here.
	if got := cert.Subject.CommonName; got != "alice" {
		t.Errorf("CommonName = %q, want the username %q", got, "alice")
	}
	if got := cert.Subject.OrganizationalUnit; len(got) != 1 || got[0] != "livedata" {
		t.Errorf("OrganizationalUnit = %q, want [livedata]", got)
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("client certificate is missing the digitalSignature key usage")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Error("client certificate must not be able to sign certificates")
	}
	if cert.IsCA {
		t.Error("client certificate must not be a CA")
	}

	if want := 1; len(cert.ExtKeyUsage) != want || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want only clientAuth", cert.ExtKeyUsage)
	}
}

func TestIssueHonoursTheRequestedDuration(t *testing.T) {
	t.Parallel()

	ca := generateCA(t)
	const d = 2 * time.Hour

	creds, err := ca.Issue("bob", "livedata", d)
	if err != nil {
		t.Fatalf("Issue(): %v", err)
	}
	cert := parseCert(t, creds.Certificate)

	if got := cert.NotAfter.Sub(cert.NotBefore); absDuration(got-d) > time.Minute {
		t.Errorf("validity window = %s, want %s", got, d)
	}
	if !creds.NotAfter.Equal(cert.NotAfter) {
		t.Errorf("NotAfter = %s, want it to match the certificate's %s", creds.NotAfter, cert.NotAfter)
	}
	if time.Until(cert.NotAfter) <= 0 {
		t.Error("issued certificate is already expired")
	}
}

func TestIssueGeneratesAFreshKeyAndSerialEachTime(t *testing.T) {
	t.Parallel()

	ca := generateCA(t)

	first, err := ca.Issue("alice", "livedata", time.Hour)
	if err != nil {
		t.Fatalf("Issue(): %v", err)
	}
	second, err := ca.Issue("alice", "livedata", time.Hour)
	if err != nil {
		t.Fatalf("Issue(): %v", err)
	}

	if first.Serial == second.Serial {
		t.Error("two issued certificates share a serial number")
	}
	if first.PrivateKey == second.PrivateKey {
		t.Error("two issued certificates share a private key")
	}
	if !strings.Contains(first.PrivateKey, "BEGIN PRIVATE KEY") {
		t.Errorf("private key is not PKCS#8 PEM:\n%s", first.PrivateKey)
	}
}

func TestGeneratedCAIsConstrained(t *testing.T) {
	t.Parallel()

	ca := generateCA(t)
	cert := parseCert(t, string(ca.CertificatePEM()))

	if !cert.IsCA {
		t.Error("generated CA is not marked as a CA")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("generated CA cannot sign certificates")
	}
	if !cert.MaxPathLenZero {
		t.Error("generated CA should not be able to issue intermediate CAs")
	}
	// A CA is not an end-entity certificate and should carry no EKU.
	if len(cert.ExtKeyUsage) != 0 {
		t.Errorf("ExtKeyUsage = %v, want none on a CA", cert.ExtKeyUsage)
	}
}

func TestWriteToProtectsThePrivateKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := generateCA(t).WriteTo(dir); err != nil {
		t.Fatalf("WriteTo(): %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "ca", "key.pem"))
	if err != nil {
		t.Fatalf("stat CA key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("CA private key mode = %#o, want 0600", perm)
	}

	dirInfo, err := os.Stat(filepath.Join(dir, "ca"))
	if err != nil {
		t.Fatalf("stat CA dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("CA directory mode = %#o, want 0700", perm)
	}
}

// A CA written out must load back and issue, so -dev-generate-ca output can be
// promoted to ca-certificate-file / ca-private-file.
func TestLoadRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := generateCA(t).WriteTo(dir); err != nil {
		t.Fatalf("WriteTo(): %v", err)
	}

	loaded, err := Load(filepath.Join(dir, "ca", "key.pem"), filepath.Join(dir, "ca", "cert.pem"))
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if _, err := loaded.Issue("alice", "livedata", time.Hour); err != nil {
		t.Errorf("Issue() after Load(): %v", err)
	}
}

func TestLoadRejects(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := generateCA(t).WriteTo(dir); err != nil {
		t.Fatalf("WriteTo(): %v", err)
	}
	key := filepath.Join(dir, "ca", "key.pem")
	cert := filepath.Join(dir, "ca", "cert.pem")

	// A key belonging to a different CA must not be paired with this cert.
	otherDir := t.TempDir()
	if err := generateCA(t).WriteTo(otherDir); err != nil {
		t.Fatalf("WriteTo(): %v", err)
	}
	otherKey := filepath.Join(otherDir, "ca", "key.pem")

	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a pem file"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}

	tests := []struct {
		name      string
		key, cert string
		want      string
	}{
		{"mismatched key and certificate", otherKey, cert, "does not match"},
		{"certificate is not PEM", key, garbage, "no PEM block"},
		{"key is not PEM", garbage, cert, "no PEM block"},
		{"missing certificate", key, filepath.Join(dir, "absent.pem"), "read"},
		{"certificate where a key belongs", cert, cert, "unexpected PEM block"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := Load(tt.key, tt.cert)
			if err == nil {
				t.Fatalf("Load() succeeded, want an error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Load() error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

// A non-CA certificate must be rejected as a signing CA.
func TestLoadRejectsANonCACertificate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ca := generateCA(t)
	if err := ca.WriteTo(dir); err != nil {
		t.Fatalf("WriteTo(): %v", err)
	}

	creds, err := ca.Issue("alice", "livedata", time.Hour)
	if err != nil {
		t.Fatalf("Issue(): %v", err)
	}
	leaf := filepath.Join(dir, "leaf.pem")
	if err := os.WriteFile(leaf, []byte(creds.Certificate), 0o600); err != nil {
		t.Fatalf("write leaf: %v", err)
	}

	if _, err := Load(filepath.Join(dir, "ca", "key.pem"), leaf); err == nil {
		t.Error("Load() accepted an end-entity certificate as a CA")
	}
}

func generateCA(t *testing.T) *CA {
	t.Helper()

	ca, err := Generate("Test Org")
	if err != nil {
		t.Fatalf("Generate(): %v", err)
	}
	return ca
}

func parseCert(t *testing.T, pemData string) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		t.Fatalf("no PEM block in:\n%s", pemData)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
