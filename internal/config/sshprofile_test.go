package config

import (
	"strings"
	"testing"
)

// SSHProfile.AllowedFor is the SSH half of the authorization decision. The VPN
// half has had a table test pinning deny-by-default since the regression that
// prompted it; this is the same guarantee, stated directly rather than only
// reached through the handlers.
func TestSSHProfileAllowedFor(t *testing.T) {
	t.Parallel()

	profile := SSHProfile{Name: "bastion", Roles: []string{"ssh-bastion", "ssh-admin"}}

	tests := []struct {
		name  string
		roles []string
		want  bool
	}{
		{"matching role", []string{"ssh-bastion"}, true},
		{"second matching role", []string{"ssh-admin"}, true},
		{"one of several matches", []string{"other", "ssh-admin"}, true},
		{"no roles at all", nil, false},
		{"empty role list", []string{}, false},
		{"unrelated role", []string{"ssh-other"}, false},
		{"a VPN role", []string{"vpn-livedata"}, false},
		{"role is a prefix", []string{"ssh-bast"}, false},
		{"role differs in case", []string{"SSH-BASTION"}, false},
		{"many unrelated roles", []string{"a", "b", "c", "d", "e", "f"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := profile.AllowedFor(tt.roles); got != tt.want {
				t.Errorf("AllowedFor(%q) = %v, want %v", tt.roles, got, tt.want)
			}
		})
	}
}

// A profile granting no roles must match nobody, however many the caller holds.
func TestSSHProfileNoRolesDeniesAll(t *testing.T) {
	t.Parallel()

	profile := SSHProfile{Name: "orphan", Principals: []string{"deploy"}}
	for _, roles := range [][]string{nil, {"any"}, {"a", "b", "c", "d", "e", "f", "g"}} {
		if profile.AllowedFor(roles) {
			t.Errorf("AllowedFor(%q) = true, want false", roles)
		}
	}
}

// Forwarding is opt-in: a profile that says nothing gets an interactive shell
// and nothing else.
func TestSSHProfileExtensions(t *testing.T) {
	t.Parallel()

	unset := SSHProfile{}.GrantedExtensions()
	if len(unset) != 2 {
		t.Fatalf("default extensions = %v, want exactly permit-pty and permit-user-rc", unset)
	}
	for _, want := range []string{"permit-pty", "permit-user-rc"} {
		if !contains(unset, want) {
			t.Errorf("default extensions missing %q", want)
		}
	}
	for _, forbidden := range []string{"permit-port-forwarding", "permit-agent-forwarding", "permit-X11-forwarding"} {
		if contains(unset, forbidden) {
			t.Errorf("%q is granted by default; forwarding must be opt-in", forbidden)
		}
	}

	explicit := SSHProfile{Extensions: []string{"permit-pty"}}.GrantedExtensions()
	if len(explicit) != 1 || explicit[0] != "permit-pty" {
		t.Errorf("explicit extensions = %v, want only what was configured", explicit)
	}
}

func TestSSHProfileValidation(t *testing.T) {
	t.Parallel()

	valid := `
ssh-profiles:
  - name: bastion
    max-session: 8h
    roles: [ssh-bastion]
    principals: [deploy, ubuntu]
`
	c := loadString(t, valid)
	p, err := c.SSHProfile("bastion")
	if err != nil {
		t.Fatalf("SSHProfile(bastion): %v", err)
	}
	if len(p.Principals) != 2 {
		t.Errorf("Principals = %v", p.Principals)
	}

	if _, err := c.SSHProfile("nope"); err == nil {
		t.Error("SSHProfile(nope) succeeded, want ErrNoProfile")
	}
}

func TestSSHProfileRejects(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, yaml, want string }{{
		name: "no principals",
		yaml: `
ssh-profiles:
  - name: bastion
    max-session: 1h
    roles: [r]`,
		want: "no principals",
	}, {
		name: "no roles",
		yaml: `
ssh-profiles:
  - name: bastion
    max-session: 1h
    principals: [deploy]`,
		want: "no roles",
	}, {
		// A principal reaches sshd's AuthorizedPrincipalsFile lookup.
		name: "principal is not a login name",
		yaml: `
ssh-profiles:
  - name: bastion
    max-session: 1h
    roles: [r]
    principals: ["root; rm -rf /"]`,
		want: "principal",
	}, {
		name: "principal starts with a digit",
		yaml: `
ssh-profiles:
  - name: bastion
    max-session: 1h
    roles: [r]
    principals: [0day]`,
		want: "principal",
	}, {
		name: "unknown extension",
		yaml: `
ssh-profiles:
  - name: bastion
    max-session: 1h
    roles: [r]
    principals: [deploy]
    extensions: [permit-everything]`,
		want: "extension",
	}, {
		name: "traversal in the name",
		yaml: `
ssh-profiles:
  - name: ../../etc/passwd
    max-session: 1h
    roles: [r]
    principals: [deploy]`,
		want: "name must match",
	}, {
		name: "duration over the ceiling",
		yaml: `
ssh-profiles:
  - name: bastion
    max-session: 720h
    roles: [r]
    principals: [deploy]`,
		want: "exceeds",
	}, {
		name: "duplicate names",
		yaml: `
ssh-profiles:
  - name: bastion
    max-session: 1h
    roles: [r]
    principals: [deploy]
  - name: bastion
    max-session: 1h
    roles: [r]
    principals: [deploy]`,
		want: "duplicate ssh profile",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := Load(writeConfig(t, tt.yaml))
			if err == nil {
				t.Fatalf("Load() succeeded, want an error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Load() error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

// An SSH-only deployment is valid: the .ovpn template is only needed when VPN
// profiles exist.
func TestSSHOnlyNeedsNoTemplate(t *testing.T) {
	t.Parallel()

	c := loadString(t, `
ssh-profiles:
  - name: bastion
    max-session: 1h
    roles: [ssh-bastion]
    principals: [deploy]
`)
	if len(c.Profiles) != 0 {
		t.Errorf("Profiles = %v, want none", c.Profiles)
	}
	if c.ProfileTemplate() != nil {
		t.Error("an SSH-only config should not have parsed a profile template")
	}
}
