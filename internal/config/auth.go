package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// AuthMode selects how Gruff establishes who the caller is.
type AuthMode string

const (
	// AuthProxy trusts identity headers set by an upstream SSO proxy. Gruff
	// authenticates nobody and must not be directly reachable.
	AuthProxy AuthMode = "proxy"
	// AuthOIDC makes Gruff the authenticator: it runs the authorization code
	// flow itself and holds the session. It is meant to be exposed.
	AuthOIDC AuthMode = "oidc"
)

const (
	defaultSessionLifetime = 8 * time.Hour
	maxSessionLifetime     = 24 * time.Hour
	defaultRolesClaim      = "groups"
)

// Auth is the authentication configuration.
type Auth struct {
	Mode AuthMode `yaml:"mode"`

	// OIDC settings, used when mode is oidc.
	Issuer          string   `yaml:"issuer"`
	ClientID        string   `yaml:"client-id"`
	ClientSecret    string   `yaml:"client-secret"`
	ClientSecretEnv string   `yaml:"client-secret-env"`
	RedirectURL     string   `yaml:"redirect-url"`
	Scopes          []string `yaml:"scopes"`
	RolesClaim      string   `yaml:"roles-claim"`
	UsernameClaim   string   `yaml:"username-claim"`

	// SessionKeyFile holds 32 random bytes, base64 or raw. Rotating it signs
	// every outstanding session out at once.
	SessionKeyFile  string   `yaml:"session-key-file"`
	SessionLifetime Duration `yaml:"session-lifetime"`

	// InsecureCookies drops the Secure attribute so a plain-HTTP development
	// instance can hold a session. Never set this in a deployment.
	InsecureCookies bool `yaml:"insecure-cookies"`

	sessionKey []byte
}

// SessionKey is the loaded 32-byte session key.
func (a *Auth) SessionKey() []byte { return a.sessionKey }

// Secret resolves the client secret, preferring the environment so it need not
// sit in a config file.
func (a *Auth) Secret() string {
	if a.ClientSecretEnv != "" {
		return os.Getenv(a.ClientSecretEnv)
	}
	return a.ClientSecret
}

// SessionDuration is how long a signed-in session lasts.
func (a *Auth) SessionDuration() time.Duration {
	if a.SessionLifetime == 0 {
		return defaultSessionLifetime
	}
	return time.Duration(a.SessionLifetime)
}

// OIDCScopes is the scope set to request, always including openid.
func (a *Auth) OIDCScopes() []string {
	if len(a.Scopes) == 0 {
		return []string{"openid", "profile", "email", "groups"}
	}
	scopes := append([]string{}, a.Scopes...)
	if !contains(scopes, "openid") {
		scopes = append([]string{"openid"}, scopes...)
	}
	return scopes
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func (a *Auth) validate() error {
	a.Mode = AuthMode(cmpOr(string(a.Mode), string(AuthProxy)))

	switch a.Mode {
	case AuthProxy:
		// Nothing else is required; identity comes from headers.
		return nil
	case AuthOIDC:
	default:
		return fmt.Errorf("mode %q must be %q or %q", a.Mode, AuthProxy, AuthOIDC)
	}

	a.RolesClaim = cmpOr(a.RolesClaim, defaultRolesClaim)
	a.UsernameClaim = cmpOr(a.UsernameClaim, "preferred_username")

	if a.Issuer == "" {
		return errors.New("oidc mode requires issuer")
	}
	if _, err := url.Parse(a.Issuer); err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	if a.ClientID == "" {
		return errors.New("oidc mode requires client-id")
	}
	if a.ClientSecret == "" && a.ClientSecretEnv == "" {
		return errors.New("oidc mode requires client-secret or client-secret-env")
	}
	if a.ClientSecretEnv != "" && a.ClientSecret != "" {
		return errors.New("set client-secret or client-secret-env, not both")
	}
	if a.ClientSecretEnv != "" && os.Getenv(a.ClientSecretEnv) == "" {
		return fmt.Errorf("client-secret-env %q is empty in the environment", a.ClientSecretEnv)
	}

	if a.RedirectURL == "" {
		return errors.New("oidc mode requires redirect-url")
	}
	redirect, err := url.Parse(a.RedirectURL)
	if err != nil {
		return fmt.Errorf("redirect-url: %w", err)
	}
	if redirect.Scheme != "http" && redirect.Scheme != "https" {
		return fmt.Errorf("redirect-url %q must be absolute http or https", a.RedirectURL)
	}
	if redirect.Scheme == "http" && !a.InsecureCookies {
		return errors.New("redirect-url is http; set insecure-cookies for local development, or use https")
	}

	if d := a.SessionDuration(); d <= 0 || d > maxSessionLifetime {
		return fmt.Errorf("session-lifetime %s must be between zero and %s", d, maxSessionLifetime)
	}

	if a.SessionKeyFile == "" {
		return errors.New("oidc mode requires session-key-file")
	}
	key, err := loadSessionKey(a.SessionKeyFile)
	if err != nil {
		return err
	}
	a.sessionKey = key

	return nil
}

// loadSessionKey accepts 32 raw bytes or a base64 encoding of them.
func loadSessionKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read session-key-file: %w", err)
	}

	if len(raw) == 32 {
		return raw, nil
	}

	trimmed := strings.TrimSpace(string(raw))
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := enc.DecodeString(trimmed); err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("session-key-file %s must hold 32 bytes, raw or base64", path)
}

func cmpOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
