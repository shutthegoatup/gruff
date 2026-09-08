package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeKey drops a 32-byte session key on disk and returns its path.
func writeKey(t *testing.T, body []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "session.key")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

func rawKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

// oidcConfig is a valid oidc-mode config with the session key at path.
func oidcConfig(keyPath string) string {
	return `
auth:
  mode: oidc
  issuer: https://auth.example.com/realms/main
  client-id: gruff
  client-secret: shh
  redirect-url: https://gruff.example.com/auth/callback
  session-key-file: ` + keyPath + `
ssh-profiles:
  - name: bastion
    max-session: 1h
    roles: [ssh-bastion]
    principals: [deploy]
`
}

func TestAuthDefaultsToProxy(t *testing.T) {
	t.Parallel()

	c := loadString(t, validProfile)
	if c.Auth.Mode != AuthProxy {
		t.Errorf("Mode = %q, want %q by default", c.Auth.Mode, AuthProxy)
	}
	// Proxy mode must not require any of the OIDC settings.
	if c.Auth.SessionKey() != nil {
		t.Error("proxy mode loaded a session key it does not need")
	}
}

func TestAuthOIDCLoads(t *testing.T) {
	t.Parallel()

	c := loadString(t, oidcConfig(writeKey(t, rawKey())))

	if c.Auth.Mode != AuthOIDC {
		t.Fatalf("Mode = %q", c.Auth.Mode)
	}
	if len(c.Auth.SessionKey()) != 32 {
		t.Errorf("SessionKey() is %d bytes, want 32", len(c.Auth.SessionKey()))
	}
	if c.Auth.SessionDuration() != defaultSessionLifetime {
		t.Errorf("SessionDuration() = %s, want the %s default", c.Auth.SessionDuration(), defaultSessionLifetime)
	}
	if c.Auth.RolesClaim != defaultRolesClaim {
		t.Errorf("RolesClaim = %q, want %q", c.Auth.RolesClaim, defaultRolesClaim)
	}
	if c.Auth.UsernameClaim != "preferred_username" {
		t.Errorf("UsernameClaim = %q", c.Auth.UsernameClaim)
	}
}

// openid is required for the flow to be OIDC at all, so it is added whatever
// the operator lists.
func TestOIDCScopesIncludeOpenID(t *testing.T) {
	t.Parallel()

	tests := map[string][]string{
		"unset":            nil,
		"without openid":   {"profile", "groups"},
		"already included": {"openid", "email"},
	}

	for name, configured := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := (&Auth{Scopes: configured}).OIDCScopes()
			if !contains(got, "openid") {
				t.Errorf("OIDCScopes() = %v, missing openid", got)
			}
			var seen int
			for _, s := range got {
				if s == "openid" {
					seen++
				}
			}
			if seen != 1 {
				t.Errorf("OIDCScopes() = %v, openid appears %d times", got, seen)
			}
		})
	}
}

// The secret should be resolvable from the environment so it need not sit in a
// config file next to everything else.
func TestSecretFromEnv(t *testing.T) {
	t.Setenv("GRUFF_TEST_SECRET", "from-env")

	if got := (&Auth{ClientSecretEnv: "GRUFF_TEST_SECRET"}).Secret(); got != "from-env" {
		t.Errorf("Secret() = %q, want the environment value", got)
	}
	if got := (&Auth{ClientSecret: "inline"}).Secret(); got != "inline" {
		t.Errorf("Secret() = %q, want the inline value", got)
	}
}

func TestSessionKeyEncodings(t *testing.T) {
	t.Parallel()

	raw := rawKey()
	encodings := map[string][]byte{
		"raw":              raw,
		"std base64":       []byte(base64.StdEncoding.EncodeToString(raw)),
		"raw std base64":   []byte(base64.RawStdEncoding.EncodeToString(raw)),
		"url base64":       []byte(base64.URLEncoding.EncodeToString(raw)),
		"base64 + newline": []byte(base64.StdEncoding.EncodeToString(raw) + "\n"),
	}

	for name, body := range encodings {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := loadString(t, oidcConfig(writeKey(t, body)))
			if got := c.Auth.SessionKey(); len(got) != 32 {
				t.Fatalf("SessionKey() is %d bytes, want 32", len(got))
			} else if string(got) != string(raw) {
				t.Error("SessionKey() did not decode to the original bytes")
			}
		})
	}
}

func TestSessionKeyWrongSize(t *testing.T) {
	t.Parallel()

	for name, body := range map[string][]byte{
		"empty":     {},
		"too short": []byte("short"),
		"31 bytes":  make([]byte, 31),
		"33 bytes":  make([]byte, 33),
		"not b64":   []byte("!!!!not base64 and not 32 bytes!!!!"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := Load(writeConfig(t, oidcConfig(writeKey(t, body))))
			if err == nil {
				t.Fatal("Load() accepted a key that is not 32 bytes")
			}
			if !strings.Contains(err.Error(), "32 bytes") {
				t.Errorf("error = %v, want it to say the key must be 32 bytes", err)
			}
		})
	}
}

func TestAuthOIDCRejects(t *testing.T) {
	t.Parallel()

	key := writeKey(t, rawKey())
	base := func(extra string) string {
		return `
auth:
  mode: oidc
` + extra + `
ssh-profiles:
  - name: bastion
    max-session: 1h
    roles: [ssh-bastion]
    principals: [deploy]
`
	}

	tests := []struct{ name, yaml, want string }{
		{"unknown mode", `
auth:
  mode: magic
ssh-profiles:
  - name: b
    max-session: 1h
    roles: [r]
    principals: [deploy]`, "must be"},

		{"no issuer", base(`  client-id: gruff
  client-secret: shh
  redirect-url: https://g.example.com/auth/callback
  session-key-file: ` + key), "issuer"},

		{"no client id", base(`  issuer: https://auth.example.com
  client-secret: shh
  redirect-url: https://g.example.com/auth/callback
  session-key-file: ` + key), "client-id"},

		{"no secret at all", base(`  issuer: https://auth.example.com
  client-id: gruff
  redirect-url: https://g.example.com/auth/callback
  session-key-file: ` + key), "client-secret"},

		{"both secret forms", base(`  issuer: https://auth.example.com
  client-id: gruff
  client-secret: shh
  client-secret-env: SOMEVAR
  redirect-url: https://g.example.com/auth/callback
  session-key-file: ` + key), "not both"},

		{"no redirect url", base(`  issuer: https://auth.example.com
  client-id: gruff
  client-secret: shh
  session-key-file: ` + key), "redirect-url"},

		{"relative redirect url", base(`  issuer: https://auth.example.com
  client-id: gruff
  client-secret: shh
  redirect-url: /auth/callback
  session-key-file: ` + key), "absolute"},

		// http without opting in would ship session cookies in the clear.
		{"http redirect without insecure-cookies", base(`  issuer: https://auth.example.com
  client-id: gruff
  client-secret: shh
  redirect-url: http://g.example.com/auth/callback
  session-key-file: ` + key), "insecure-cookies"},

		{"no session key", base(`  issuer: https://auth.example.com
  client-id: gruff
  client-secret: shh
  redirect-url: https://g.example.com/auth/callback`), "session-key-file"},

		{"missing session key file", base(`  issuer: https://auth.example.com
  client-id: gruff
  client-secret: shh
  redirect-url: https://g.example.com/auth/callback
  session-key-file: /nonexistent/session.key`), "read session-key-file"},

		{"session lifetime over the ceiling", base(`  issuer: https://auth.example.com
  client-id: gruff
  client-secret: shh
  redirect-url: https://g.example.com/auth/callback
  session-lifetime: 72h
  session-key-file: ` + key), "session-lifetime"},
	}

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

// An empty client-secret-env is a misconfiguration that would otherwise only
// surface as a failed token exchange at the first sign-in.
func TestAuthEmptySecretEnv(t *testing.T) {
	t.Setenv("GRUFF_EMPTY_SECRET", "")

	yaml := `
auth:
  mode: oidc
  issuer: https://auth.example.com
  client-id: gruff
  client-secret-env: GRUFF_EMPTY_SECRET
  redirect-url: https://g.example.com/auth/callback
  session-key-file: ` + writeKey(t, rawKey()) + `
ssh-profiles:
  - name: bastion
    max-session: 1h
    roles: [ssh-bastion]
    principals: [deploy]
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("Load() accepted an empty client-secret-env")
	}
	if !strings.Contains(err.Error(), "empty in the environment") {
		t.Errorf("error = %v", err)
	}
}

func TestSessionDuration(t *testing.T) {
	t.Parallel()

	a := &Auth{SessionLifetime: Duration(2 * time.Hour)}
	if a.SessionDuration() != 2*time.Hour {
		t.Errorf("SessionDuration() = %s, want 2h", a.SessionDuration())
	}
}
