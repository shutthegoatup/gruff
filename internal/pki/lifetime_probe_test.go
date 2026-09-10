package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// caExpiringIn builds a CA whose own certificate runs out after d.
func caExpiringIn(t *testing.T, d time.Duration) *CA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := newSerial()
	now := time.Now().UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Expiring CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(d),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{key: key, cert: cert}
}

func TestProbeCertOutlivingItsCA(t *testing.T) {
	// A CA with an hour left, issuing the shipped livedata profile's 2h.
	ca := caExpiringIn(t, time.Hour)

	creds, err := ca.Issue("alice", "livedata", 2*time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	block, _ := pem.Decode([]byte(creds.Certificate))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("CA expires   %s", ca.cert.NotAfter.Format(time.RFC3339))
	t.Logf("cert expires %s", leaf.NotAfter.Format(time.RFC3339))
	t.Logf("the certificate outlives its issuer by %s", leaf.NotAfter.Sub(ca.cert.NotAfter))

	// What OpenVPN does on every connection.
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "cert.pem")
	os.WriteFile(caPath, ca.CertificatePEM(), 0o644)
	os.WriteFile(certPath, []byte(creds.Certificate), 0o644)

	// Verified as at a moment after the CA lapses but before the cert would.
	at := ca.cert.NotAfter.Add(time.Minute)
	out, err := exec.Command(openssl, "verify",
		"-attime", fmt.Sprint(at.Unix()),
		"-CAfile", caPath, certPath).CombinedOutput()
	t.Logf("openssl verify at %s: err=%v\n%s", at.Format(time.RFC3339), err, out)
}

func TestProbeLoadingAnExpiredCA(t *testing.T) {
	ca := caExpiringIn(t, -time.Minute) // lapsed sixty seconds ago
	dir := t.TempDir()
	if err := ca.WriteTo(dir); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(filepath.Join(dir, "ca", "key.pem"), filepath.Join(dir, "ca", "cert.pem"))
	t.Logf("Load of a CA that expired a minute ago: err=%v", err)
	if err == nil {
		creds, err := loaded.Issue("alice", "livedata", 2*time.Hour)
		t.Logf("and it issued a certificate: err=%v serial=%s", err, creds.Serial)
	}
}
