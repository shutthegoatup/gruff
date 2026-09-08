// Package authsession carries a signed-in user in an AES-GCM cookie.
//
// Stateless by construction, so a restart or a second replica serves an
// existing session. The trade is no server-side revocation before expiry;
// rotating the key invalidates every outstanding session.
package authsession

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// CookieName binds the session to this exact origin. __Host- requires Secure,
// so InsecureCookieName is used when that is off - keeping the prefix there
// yields a cookie every browser refuses to store.
const (
	CookieName         = "__Host-gruff"
	InsecureCookieName = "gruff"
)

// Name is the cookie name this codec issues and reads.
func (c *Codec) Name() string {
	if c.secure {
		return CookieName
	}
	return InsecureCookieName
}

// maxCookieSize guards against emitting a cookie browsers will silently drop.
const maxCookieSize = 3800

// Purpose binds a ciphertext to what it was sealed for.
//
// The session cookie and the in-flight login cookie are sealed under the same
// key, and their payloads share JSON field names by coincidence rather than by
// design. Without this, a login cookie - handed to anyone who visits
// /auth/login, and carrying a value they chose - decrypts cleanly as a session,
// and only a type mismatch stops it being read as one. That is not a control.
//
// A purpose is the AEAD's additional data, so opening under the wrong one fails
// the tag check. The version suffix is there to invalidate outstanding cookies
// deliberately, should the payload ever change shape.
type Purpose string

const (
	// SessionPurpose seals a signed-in user.
	SessionPurpose Purpose = "gruff/session/v1"
	// FlowPurpose seals a login that has not completed yet.
	FlowPurpose Purpose = "gruff/flow/v1"
)

var (
	// ErrNoSession means the request carried no session cookie at all.
	ErrNoSession = errors.New("no session")
	// ErrInvalid means a cookie was present but is not one we issued, or has
	// expired. The two are deliberately indistinguishable to the caller.
	ErrInvalid = errors.New("invalid session")
)

// User is what a signed-in session carries. It is exactly the identity the
// trusted-header mode reads from headers, so the rest of the portal does not
// care which way the caller arrived.
type User struct {
	Username string    `json:"u"`
	Fullname string    `json:"n,omitempty"`
	Roles    []string  `json:"r,omitempty"`
	Expires  time.Time `json:"e"`
}

// Expired reports whether the session is past its lifetime.
func (u User) Expired(now time.Time) bool { return now.After(u.Expires) }

// Codec seals and opens session cookies.
type Codec struct {
	aead   cipher.AEAD
	secure bool
}

// NewCodec builds a codec from a 32-byte key. secure should only be false for
// local development over plain HTTP.
func NewCodec(key []byte, secure bool) (*Codec, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("session key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("build cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("build AEAD: %w", err)
	}
	return &Codec{aead: aead, secure: secure}, nil
}

// GenerateKey returns a fresh 32-byte session key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	return key, nil
}

// SealRaw encrypts arbitrary bytes under the session key, so rotating it
// invalidates in-flight logins too. The purpose is authenticated alongside the
// payload: a ciphertext sealed for one cannot be opened as another.
func (c *Codec) SealRaw(purpose Purpose, plaintext []byte) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	sealed := c.aead.Seal(nonce, nonce, plaintext, []byte(purpose))
	value := base64.RawURLEncoding.EncodeToString(sealed)
	if len(value) > maxCookieSize {
		return "", fmt.Errorf("cookie is %d bytes, over the %d limit", len(value), maxCookieSize)
	}
	return value, nil
}

// OpenRaw reverses [Codec.SealRaw]. It fails unless the purpose matches the one
// the value was sealed with.
func (c *Codec) OpenRaw(purpose Purpose, value string) ([]byte, error) {
	// Strict, so a cookie has exactly one spelling. Without it the trailing
	// bits of the last character are ignored, and several distinct cookie
	// strings decode to the same session.
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(sealed) < c.aead.NonceSize() {
		return nil, ErrInvalid
	}

	nonce, ciphertext := sealed[:c.aead.NonceSize()], sealed[c.aead.NonceSize():]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, []byte(purpose))
	if err != nil {
		return nil, ErrInvalid
	}
	return plaintext, nil
}

// Seal encodes and encrypts a session into a cookie ready to be set.
func (c *Codec) Seal(u User) (*http.Cookie, error) {
	plaintext, err := json.Marshal(u)
	if err != nil {
		return nil, fmt.Errorf("encode session: %w", err)
	}

	value, err := c.SealRaw(SessionPurpose, plaintext)
	if err != nil {
		return nil, err
	}

	return &http.Cookie{
		Name:     c.Name(),
		Value:    value,
		Path:     "/",
		Expires:  u.Expires,
		MaxAge:   int(time.Until(u.Expires).Seconds()),
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

// Open reads and verifies the session on a request.
func (c *Codec) Open(r *http.Request) (User, error) {
	cookie, err := r.Cookie(c.Name())
	if err != nil {
		return User{}, ErrNoSession
	}

	// Tampered, truncated, or sealed under a rotated key: all the same to us.
	plaintext, err := c.OpenRaw(SessionPurpose, cookie.Value)
	if err != nil {
		return User{}, ErrInvalid
	}

	var u User
	if err := json.Unmarshal(plaintext, &u); err != nil {
		return User{}, ErrInvalid
	}
	// The cookie's own expiry is advisory - a client controls what it sends -
	// so the authenticated payload carries the real deadline.
	if u.Expired(time.Now()) {
		return User{}, ErrInvalid
	}
	return u, nil
}

// Clear returns a cookie that removes any existing session.
func (c *Codec) Clear() *http.Cookie {
	return &http.Cookie{
		Name:     c.Name(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	}
}
