package sshca

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeKRL builds a list and drops it on disk for ssh-keygen to read.
func writeKRL(t *testing.T, ca *CA, serials []uint64) string {
	t.Helper()

	raw, err := ca.KRL(serials, time.Now())
	if err != nil {
		t.Fatalf("KRL: %v", err)
	}
	path := filepath.Join(t.TempDir(), "krl")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write krl: %v", err)
	}
	return path
}

func sshKeygen(t *testing.T) string {
	t.Helper()

	path, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not available")
	}
	return path
}

// The format is hand-assembled, so the test that matters is whether OpenSSH
// itself can read it.
func TestKRLIsReadableByOpenSSH(t *testing.T) {
	t.Parallel()

	keygen := sshKeygen(t)
	path := writeKRL(t, generateCA(t), []uint64{7, 99, 12345})

	out, err := exec.Command(keygen, "-Ql", "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -Ql rejected the KRL: %v\n%s", err, out)
	}
	for _, want := range []string{"serial: 7", "serial: 99", "serial: 12345"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("KRL listing is missing %q:\n%s", want, out)
		}
	}
}

// The point of the list: a revoked certificate must test as revoked, and an
// unrevoked one must not.
func TestKRLRevokesTheRightCertificates(t *testing.T) {
	t.Parallel()

	keygen := sshKeygen(t)
	ca := generateCA(t)
	dir := t.TempDir()

	revoked, err := ca.Issue("alice", "bastion", []string{"deploy"}, time.Hour, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	kept, err := ca.Issue("bob", "bastion", []string{"deploy"}, time.Hour, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	path := writeKRL(t, ca, []uint64{revoked.Serial})

	for name, tc := range map[string]struct {
		cert        Credentials
		wantRevoked bool
	}{
		"listed serial":   {revoked, true},
		"unlisted serial": {kept, false},
	} {
		t.Run(name, func(t *testing.T) {
			certPath := filepath.Join(dir, name+"-cert.pub")
			if err := os.WriteFile(certPath, []byte(tc.cert.Certificate+"\n"), 0o644); err != nil {
				t.Fatalf("write cert: %v", err)
			}

			// ssh-keygen -Qf exits non-zero when the key is revoked.
			err := exec.Command(keygen, "-Q", "-f", path, certPath).Run()
			gotRevoked := err != nil
			if gotRevoked != tc.wantRevoked {
				t.Errorf("revoked = %v, want %v", gotRevoked, tc.wantRevoked)
			}
		})
	}
}

// sshd treats a missing RevokedKeys file as a configuration error and refuses
// every connection, so an empty list has to be a valid one.
func TestKRLEmptyIsValid(t *testing.T) {
	t.Parallel()

	keygen := sshKeygen(t)
	path := writeKRL(t, generateCA(t), nil)

	out, err := exec.Command(keygen, "-Ql", "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen rejected an empty KRL: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "serial:") {
		t.Errorf("empty KRL lists a serial:\n%s", out)
	}
}

// A list built by one CA must not revoke another's certificates, or a shared
// serial space would revoke things it never issued.
func TestKRLIsScopedToItsCA(t *testing.T) {
	t.Parallel()

	keygen := sshKeygen(t)
	mine, other := generateCA(t), generateCA(t)

	cert, err := other.Issue("alice", "bastion", []string{"deploy"}, time.Hour, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	certPath := filepath.Join(t.TempDir(), "cert.pub")
	if err := os.WriteFile(certPath, []byte(cert.Certificate+"\n"), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	// Same serial, different authority: it must not be considered revoked.
	path := writeKRL(t, mine, []uint64{cert.Serial})
	if err := exec.Command(keygen, "-Q", "-f", path, certPath).Run(); err != nil {
		t.Error("a KRL revoked a certificate issued by a different CA")
	}
}

// Serial 0 means "unset" in a certificate; revoking it would match every
// certificate that has no serial.
func TestKRLRejectsSerialZero(t *testing.T) {
	t.Parallel()

	if _, err := generateCA(t).KRL([]uint64{0}, time.Now()); err == nil {
		t.Error("KRL accepted serial 0")
	}
}
