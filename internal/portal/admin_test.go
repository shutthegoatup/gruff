package portal

import (
	"net/http"
	"strings"
	"testing"
)

const adminRole = "gruff-admin"

// Without admin-roles configured nobody is an administrator, so the default
// build is checked separately from the one that grants it.
func TestNoAdminByDefault(t *testing.T) {
	t.Parallel()

	h := newTestPortal(t)
	request(t, h, http.MethodPost, "/profile/livedata/issue", "alice", "vpn-livedata")

	w := request(t, h, http.MethodGet, "/issued", "bob", "vpn-livedata,"+adminRole)
	body := w.Body.String()

	if strings.Contains(body, "ADMIN VIEW") {
		t.Error("a role that is not configured as admin got the admin view")
	}
	if strings.Contains(body, "alice") {
		t.Error("bob was shown alice's session without admin-roles configured")
	}
}

func TestAdminSeesEverySession(t *testing.T) {
	t.Parallel()

	h := newTestPortalWithAdmin(t)
	request(t, h, http.MethodPost, "/profile/livedata/issue", "alice", "vpn-livedata")
	request(t, h, http.MethodPost, "/ssh/bastion/issue", "carol", "ssh-bastion")

	w := request(t, h, http.MethodGet, "/issued", "auditor", adminRole)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	body := w.Body.String()
	for _, want := range []string{"ADMIN VIEW", "alice", "carol", "livedata", "bastion"} {
		if !strings.Contains(body, want) {
			t.Errorf("admin view is missing %q", want)
		}
	}
}

// The whole point of the boundary: a non-admin still sees only their own.
func TestNonAdminStillScoped(t *testing.T) {
	t.Parallel()

	h := newTestPortalWithAdmin(t)
	request(t, h, http.MethodPost, "/profile/livedata/issue", "alice", "vpn-livedata")

	w := request(t, h, http.MethodGet, "/issued", "bob", "vpn-livedata")
	body := w.Body.String()

	if strings.Contains(body, "ADMIN VIEW") {
		t.Error("a plain user was shown the admin view")
	}
	if strings.Contains(body, "alice") {
		t.Error("a plain user was shown another user's session")
	}
}

func TestAdminCanRevokeAnyones(t *testing.T) {
	t.Parallel()

	h := newTestPortalWithAdmin(t)
	serial := issueVPN(t, h, "alice")

	w := request(t, h, http.MethodPost, "/issued/"+serial+"/revoke", "auditor", adminRole)
	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", w.Code)
	}
}

// Non-admins must still be unable to revoke what they do not own, even now
// that some callers can.
func TestNonAdminCannotRevokeAnothers(t *testing.T) {
	t.Parallel()

	h := newTestPortalWithAdmin(t)
	serial := issueVPN(t, h, "alice")

	w := request(t, h, http.MethodPost, "/issued/"+serial+"/revoke", "mallory", "vpn-livedata")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// An admin role alone must not grant a profile: administration is about seeing
// and revoking, not about being issued credentials.
func TestAdminRoleGrantsNoProfiles(t *testing.T) {
	t.Parallel()

	h := newTestPortalWithAdmin(t)

	if w := request(t, h, http.MethodPost, "/profile/livedata/issue", "auditor", adminRole); w.Code != http.StatusForbidden {
		t.Errorf("VPN issue status = %d, want 403", w.Code)
	}
	if w := request(t, h, http.MethodPost, "/ssh/bastion/issue", "auditor", adminRole); w.Code != http.StatusForbidden {
		t.Errorf("SSH issue status = %d, want 403", w.Code)
	}
}
