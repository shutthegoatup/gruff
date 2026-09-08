package portal

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/shutthegoatup/gruff/internal/pki"
)

// issueVPN downloads a profile and returns the serial it was issued under.
func issueVPN(t *testing.T, h http.Handler, user string) string {
	t.Helper()

	w := request(t, h, http.MethodPost, "/profile/livedata/issue", user, "vpn-livedata")
	if w.Code != http.StatusOK {
		t.Fatalf("issue: status %d", w.Code)
	}

	block, _ := pem.Decode([]byte(certPEM(t, w.Body.String())))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert.SerialNumber.String()
}

// certPEM pulls the client certificate out of the <cert> block. The profile
// also carries the CA in <ca>, which comes first.
func certPEM(t *testing.T, ovpn string) string {
	t.Helper()

	_, rest, ok := strings.Cut(ovpn, "<cert>")
	if !ok {
		t.Fatal("profile has no <cert> block")
	}
	body, _, ok := strings.Cut(rest, "</cert>")
	if !ok {
		t.Fatal("profile has an unterminated <cert> block")
	}
	return strings.TrimSpace(body)
}

func TestRevoke(t *testing.T) {
	t.Parallel()

	h := newTestPortal(t)
	serial := issueVPN(t, h, "alice")

	w := request(t, h, http.MethodPost, "/issued/"+serial+"/revoke", "alice", "vpn-livedata")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
}

// A serial is not a capability: holding one must not let another user revoke it.
func TestRevokeRejectsAnotherUsersSerial(t *testing.T) {
	t.Parallel()

	h := newTestPortal(t)
	serial := issueVPN(t, h, "alice")

	w := request(t, h, http.MethodPost, "/issued/"+serial+"/revoke", "mallory", "vpn-livedata")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRevokeRejects(t *testing.T) {
	t.Parallel()

	h := newTestPortal(t)

	tests := map[string]struct {
		user, serial, roles string
		want                int
	}{
		"unknown serial":   {"alice", "123456789", "vpn-livedata", http.StatusForbidden},
		"no user":          {"", "123456789", "vpn-livedata", http.StatusForbidden},
		"empty-ish serial": {"alice", "0", "vpn-livedata", http.StatusForbidden},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := request(t, h, http.MethodPost, "/issued/"+tt.serial+"/revoke", tt.user, tt.roles)
			if w.Code != tt.want {
				t.Errorf("status = %d, want %d", w.Code, tt.want)
			}
		})
	}
}

// Revocation is state-changing, so it must not be reachable by navigation.
func TestRevokeRejectsGET(t *testing.T) {
	t.Parallel()

	w := request(t, newTestPortal(t), http.MethodGet, "/issued/123/revoke", "alice", "vpn-livedata")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestMemoryStoreRevocations(t *testing.T) {
	t.Parallel()

	var s MemoryStore
	ctx := context.Background()
	until := time.Now().Add(time.Hour)

	if err := s.Revoke(ctx, Revocation{Serial: "1", Kind: KindVPN, Until: until}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := s.Revoke(ctx, Revocation{Serial: "2", Kind: KindSSH, Until: until}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// Revoking twice must not double-list.
	if err := s.Revoke(ctx, Revocation{Serial: "1", Kind: KindVPN, Until: until}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	vpn, err := s.Revocations(ctx, KindVPN)
	if err != nil {
		t.Fatalf("Revocations: %v", err)
	}
	if len(vpn) != 1 || vpn[0].Serial != "1" {
		t.Errorf("VPN revocations = %+v, want just serial 1", vpn)
	}

	ssh, err := s.Revocations(ctx, KindSSH)
	if err != nil {
		t.Fatalf("Revocations: %v", err)
	}
	if len(ssh) != 1 || ssh[0].Serial != "2" {
		t.Errorf("SSH revocations = %+v, want just serial 2", ssh)
	}
}

// Once the certificate would have expired the entry is dead weight, and a list
// that only grows is its own problem.
func TestRevocationsDropExpiredEntries(t *testing.T) {
	t.Parallel()

	var s MemoryStore
	ctx := context.Background()

	if err := s.Revoke(ctx, Revocation{Serial: "old", Kind: KindVPN, Until: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := s.Revoke(ctx, Revocation{Serial: "live", Kind: KindVPN, Until: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, err := s.Revocations(ctx, KindVPN)
	if err != nil {
		t.Fatalf("Revocations: %v", err)
	}
	if len(got) != 1 || got[0].Serial != "live" {
		t.Errorf("revocations = %+v, want only the unexpired one", got)
	}
}

func TestCRL(t *testing.T) {
	t.Parallel()

	ca, err := pki.Generate("Test Org")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	now := time.Now()
	raw, err := ca.CRL([]pki.Revoked{
		{Serial: "12345", At: now},
		{Serial: "67890", At: now},
	}, now)
	if err != nil {
		t.Fatalf("CRL: %v", err)
	}

	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "X509 CRL" {
		t.Fatalf("not a PEM CRL:\n%s", raw)
	}

	list, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	// It must verify under the CA, or OpenVPN will ignore it.
	if err := list.CheckSignatureFrom(caCert(t, ca)); err != nil {
		t.Errorf("CRL does not verify against its CA: %v", err)
	}
	if len(list.RevokedCertificateEntries) != 2 {
		t.Fatalf("%d entries, want 2", len(list.RevokedCertificateEntries))
	}
	if list.RevokedCertificateEntries[0].SerialNumber.Cmp(big.NewInt(12345)) != 0 {
		t.Errorf("first serial = %s", list.RevokedCertificateEntries[0].SerialNumber)
	}
	if !list.NextUpdate.After(list.ThisUpdate) {
		t.Error("NextUpdate must be after ThisUpdate or the list reads as stale")
	}
}

// An empty CRL is what tells a server the list is current rather than missing.
func TestCRLEmptyIsStillValid(t *testing.T) {
	t.Parallel()

	ca, err := pki.Generate("Test Org")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	raw, err := ca.CRL(nil, time.Now())
	if err != nil {
		t.Fatalf("CRL: %v", err)
	}
	block, _ := pem.Decode(raw)
	list, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if len(list.RevokedCertificateEntries) != 0 {
		t.Errorf("%d entries, want none", len(list.RevokedCertificateEntries))
	}
	if err := list.CheckSignatureFrom(caCert(t, ca)); err != nil {
		t.Errorf("empty CRL does not verify: %v", err)
	}
}

func TestCRLRejectsANonNumericSerial(t *testing.T) {
	t.Parallel()

	ca, err := pki.Generate("Test Org")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := ca.CRL([]pki.Revoked{{Serial: "not-a-number"}}, time.Now()); err == nil {
		t.Error("CRL accepted a serial that is not an integer")
	}
}

func caCert(t *testing.T, ca *pki.CA) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode(ca.CertificatePEM())
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return cert
}
