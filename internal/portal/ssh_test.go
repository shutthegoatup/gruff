package portal

import (
	"net/http"
	"strings"
	"testing"

	"github.com/shutthegoatup/gruff/internal/config"
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

// An operator following the setup page has to be able to find the KRL. sshd
// does not complain about a missing RevokedKeys file - it starts, sshd -t
// passes, and then refuses every public key - so the page has to name where
// the file comes from rather than leave it to be discovered that way.
func TestSetupPageSaysWhereTheKRLComesFrom(t *testing.T) {
	t.Parallel()

	p, h := buildTestPortal(t, 0)
	p.cfg.ConfigdirEnabled = true
	p.cfg.ConfigdirPath = "/var/lib/gruff/profiles"

	body := request(t, h, http.MethodGet, "/setup", "alice", "ssh-bastion").Body.String()
	if !strings.Contains(body, "RevokedKeys") {
		t.Fatal("setup page does not mention RevokedKeys at all")
	}

	source := p.cfg.ConfigdirPath + "/krl"
	if !strings.Contains(body, source) {
		t.Errorf("setup page never says the KRL is written to %s", source)
	}
}

// The snippet is generated per deployment, so it must hold together when the
// portal publishes nothing.
func TestSSHDConfigWithoutAConfigdir(t *testing.T) {
	t.Parallel()

	got := sshdConfig(&config.Config{})
	if strings.Contains(got, "/krl") {
		t.Errorf("points at a KRL the portal does not write:\n%s", got)
	}
	if !strings.Contains(got, "configdir-path") {
		t.Errorf("does not say how to get one:\n%s", got)
	}
}
