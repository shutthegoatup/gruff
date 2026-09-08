// Package authsession carries a signed-in user in an encrypted cookie.
//
// The session is stateless by construction: everything needed to identify the
// caller travels in the cookie, authenticated and encrypted with a key only
// Gruff holds. That is what lets a restart, a redeploy or a second replica
// serve an existing session without a shared database.
//
// The trade is that a session cannot be revoked server-side before it expires.
// Lifetimes are therefore short, and the key can be rotated to invalidate every
// outstanding session at once.
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

// CookieName is the cookie the session travels in over HTTPS. The __Host-
// prefix binds it to this exact origin: browsers reject it unless it is
// Secure, path=/ and carries no Domain, which stops a sibling subdomain from
// setting one.
const CookieName = "__Host-gruff"

// InsecureCookieName is used only when the Secure attribute is off, for local
// development over plain HTTP. The __Host- prefix requires Secure, so keeping
// it there would produce a cookie every browser refuses to store.
const InsecureCookieName = "gruff"

// Name is the cookie name this codec issues and reads.
func (c *Codec) Name() string {
	if c.secure {
		return CookieName
	}
	return InsecureCookieName
}

// maxCookieSize guards against emitting a cookie browsers will silently drop.
const maxCookieSize = 3800

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

// NewCodec builds a codec from a 32-byte key.
//
// secure controls the Secure attribute; it exists only so that a plain-HTTP
// development instance can still hold a session. In any real deployment the
// portal is behind TLS and this is true.
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

// SealRaw encrypts arbitrary bytes under the same key, for cookies that are not
// sessions - the in-flight login state, for instance. Keeping them on one key
// means rotating it invalidates everything at once.
func (c *Codec) SealRaw(plaintext []byte) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	sealed := c.aead.Seal(nonce, nonce, plaintext, nil)
	value := base64.RawURLEncoding.EncodeToString(sealed)
	if len(value) > maxCookieSize {
		return "", fmt.Errorf("cookie is %d bytes, over the %d limit", len(value), maxCookieSize)
	}
	return value, nil
}

// OpenRaw reverses [Codec.SealRaw].
func (c *Codec) OpenRaw(value string) ([]byte, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(sealed) < c.aead.NonceSize() {
		return nil, ErrInvalid
	}

	nonce, ciphertext := sealed[:c.aead.NonceSize()], sealed[c.aead.NonceSize():]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
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

	value, err := c.SealRaw(plaintext)
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
	plaintext, err := c.OpenRaw(cookie.Value)
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
