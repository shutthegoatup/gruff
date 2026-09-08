package portal

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The same deny-by-default invariant the VPN side pins, on the SSH path.
func TestSSHIssueDeniesAUserWithoutTheRole(t *testing.T) {
	t.Parallel()

	h := newTestPortal(t)
	denied := []struct{ name, roles string }{
		{"no roles", ""},
		{"unrelated role", "ssh-other"},
		{"the other profile's role", "ssh-dbadmin"},
		{"a VPN role", "vpn-livedata"},
		{"role is a prefix", "ssh-bast"},
	}

	for _, tt := range denied {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := request(t, h, http.MethodPost, "/ssh/bastion/issue", "mallory", tt.roles)
			if w.Code != http.StatusForbidden {
				t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
			}
			if strings.Contains(w.Body.String(), "PRIVATE KEY") {
				t.Error("a denied request was served key material")
			}
		})
	}
}

func TestSSHIssueServesABundleToAnAuthorisedUser(t *testing.T) {
	t.Parallel()

	w := request(t, newTestPortal(t), http.MethodPost, "/ssh/bastion/issue", "alice", "ssh-bastion")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	files := readBundle(t, w.Body.Bytes())

	key, ok := files["gruff-bastion/id_ed25519"]
	if !ok {
		t.Fatalf("bundle has no private key; contains %v", keysOf(files))
	}
	if _, err := ssh.ParsePrivateKey([]byte(key.body)); err != nil {
		t.Errorf("private key does not parse: %v", err)
	}
	// The mode is the whole reason this ships as a tarball: ssh refuses a
	// world-readable key.
	if key.mode != 0o600 {
		t.Errorf("private key mode = %#o, want 0600", key.mode)
	}

	certFile, ok := files["gruff-bastion/id_ed25519-cert.pub"]
	if !ok {
		t.Fatal("bundle has no certificate")
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certFile.body))
	if err != nil {
		t.Fatalf("certificate does not parse: %v", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed %T, want a certificate", pub)
	}
	if cert.KeyId != "alice@bastion" {
		t.Errorf("KeyId = %q, want alice@bastion", cert.KeyId)
	}
	if len(cert.ValidPrincipals) != 2 {
		t.Errorf("ValidPrincipals = %v, want the two configured logins", cert.ValidPrincipals)
	}

	if cfg, ok := files["gruff-bastion/config"]; !ok {
		t.Error("bundle has no ssh_config fragment")
	} else if !strings.Contains(cfg.body, "CertificateFile") {
		t.Error("ssh_config fragment does not reference the certificate")
	}
}

func TestSSHIssueRejectsGET(t *testing.T) {
	t.Parallel()

	w := request(t, newTestPortal(t), http.MethodGet, "/ssh/bastion/issue", "alice", "ssh-bastion")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestSSHIssueRequiresAnAuthenticatedUser(t *testing.T) {
	t.Parallel()

	w := request(t, newTestPortal(t), http.MethodPost, "/ssh/bastion/issue", "", "ssh-bastion")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestSSHIndexMarksOnlyPermittedProfiles(t *testing.T) {
	t.Parallel()

	w := request(t, newTestPortal(t), http.MethodGet, "/ssh", "alice", "ssh-bastion")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "/ssh/bastion/issue") {
		t.Error("the permitted profile has no issue form")
	}
	if strings.Contains(body, "/ssh/dbadmin/issue") {
		t.Error("an unpermitted profile was given an issue form")
	}
	// Principals of a profile the caller cannot use should not be disclosed.
	if strings.Contains(body, "postgres") {
		t.Error("an unpermitted profile's principals were disclosed")
	}
}

// The setup page publishes only public material.
func TestSetupPublishesCAPublicKeysOnly(t *testing.T) {
	t.Parallel()

	w := request(t, newTestPortal(t), http.MethodGet, "/setup", "alice", "ssh-bastion")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "ssh-ed25519 ") {
		t.Error("setup page does not show the SSH CA public key")
	}
	if !strings.Contains(body, "TrustedUserCAKeys") {
		t.Error("setup page does not show the sshd_config directive")
	}
	if !strings.Contains(body, "BEGIN CERTIFICATE") {
		t.Error("setup page does not show the VPN CA certificate")
	}
	if strings.Contains(body, "PRIVATE KEY") {
		t.Fatal("setup page leaked private key material")
	}
}

type bundleFile struct {
	mode int64
	body string
}

func readBundle(t *testing.T, raw []byte) map[string]bundleFile {
	t.Helper()

	gz, err := gzip.NewReader(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("open gzip: %v", err)
	}
	defer gz.Close()

	files := map[string]bundleFile{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s: %v", h.Name, err)
		}
		files[h.Name] = bundleFile{mode: h.Mode, body: string(body)}
	}
	return files
}

func keysOf(m map[string]bundleFile) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
