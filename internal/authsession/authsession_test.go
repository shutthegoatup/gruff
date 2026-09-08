package authsession

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newCodec(t *testing.T) *Codec {
	t.Helper()

	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey(): %v", err)
	}
	c, err := NewCodec(key, true)
	if err != nil {
		t.Fatalf("NewCodec(): %v", err)
	}
	return c
}

func alice() User {
	return User{
		Username: "alice.mercer",
		Fullname: "Alice Mercer",
		Roles:    []string{"vpn-livedata", "ssh-bastion"},
		Expires:  time.Now().Add(time.Hour),
	}
}

func requestWith(c *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://gruff.example.com/", nil)
	if c != nil {
		r.AddCookie(c)
	}
	return r
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	c := newCodec(t)
	want := alice()

	cookie, err := c.Seal(want)
	if err != nil {
		t.Fatalf("Seal(): %v", err)
	}

	got, err := c.Open(requestWith(cookie))
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	if got.Username != want.Username || got.Fullname != want.Fullname {
		t.Errorf("identity = %+v, want %+v", got, want)
	}
	if len(got.Roles) != 2 || got.Roles[0] != "vpn-livedata" {
		t.Errorf("Roles = %v, want the sealed roles", got.Roles)
	}
}

// The whole point of the cookie is that its contents are not readable or
// forgeable by the client holding it.
func TestSealedCookieIsOpaque(t *testing.T) {
	t.Parallel()

	cookie, err := newCodec(t).Seal(alice())
	if err != nil {
		t.Fatalf("Seal(): %v", err)
	}

	for _, leak := range []string{"alice", "Mercer", "vpn-livedata", "ssh-bastion"} {
		if strings.Contains(cookie.Value, leak) {
			t.Errorf("cookie value leaks %q in plaintext", leak)
		}
	}
}

func TestTamperedCookieIsRejected(t *testing.T) {
	t.Parallel()

	c := newCodec(t)
	cookie, err := c.Seal(alice())
	if err != nil {
		t.Fatalf("Seal(): %v", err)
	}

	tests := map[string]string{
		"flipped byte":  flipLast(cookie.Value),
		"truncated":     cookie.Value[:len(cookie.Value)-4],
		"empty":         "",
		"not base64":    "!!!not-base64!!!",
		"short garbage": "AAAA",
	}

	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			bad := &http.Cookie{Name: CookieName, Value: value}
			if _, err := c.Open(requestWith(bad)); !errors.Is(err, ErrInvalid) {
				t.Errorf("Open() error = %v, want ErrInvalid", err)
			}
		})
	}
}

// A session sealed under one key must not open under another - this is what
// makes key rotation an effective mass revocation.
func TestKeyRotationInvalidatesSessions(t *testing.T) {
	t.Parallel()

	cookie, err := newCodec(t).Seal(alice())
	if err != nil {
		t.Fatalf("Seal(): %v", err)
	}

	if _, err := newCodec(t).Open(requestWith(cookie)); !errors.Is(err, ErrInvalid) {
		t.Errorf("Open() under a rotated key = %v, want ErrInvalid", err)
	}
}

// Expiry is enforced from the authenticated payload, not the cookie attribute,
// which a client controls.
func TestExpiryIsEnforcedFromThePayload(t *testing.T) {
	t.Parallel()

	c := newCodec(t)
	expired := alice()
	expired.Expires = time.Now().Add(-time.Minute)

	cookie, err := c.Seal(expired)
	if err != nil {
		t.Fatalf("Seal(): %v", err)
	}

	// Present it with attributes that claim it is still fresh; the sealed
	// deadline must still win.
	cookie.Expires = time.Now().Add(time.Hour)
	cookie.MaxAge = 3600

	if _, err := c.Open(requestWith(cookie)); !errors.Is(err, ErrInvalid) {
		t.Errorf("Open() on an expired session = %v, want ErrInvalid", err)
	}
}

func TestMissingCookie(t *testing.T) {
	t.Parallel()

	if _, err := newCodec(t).Open(requestWith(nil)); !errors.Is(err, ErrNoSession) {
		t.Errorf("Open() with no cookie = %v, want ErrNoSession", err)
	}
}

func TestCookieAttributes(t *testing.T) {
	t.Parallel()

	cookie, err := newCodec(t).Seal(alice())
	if err != nil {
		t.Fatalf("Seal(): %v", err)
	}

	if cookie.Name != "__Host-gruff" {
		t.Errorf("Name = %q, want the __Host- prefixed name", cookie.Name)
	}
	if !cookie.HttpOnly {
		t.Error("cookie is readable from JavaScript")
	}
	if !cookie.Secure {
		t.Error("cookie is not marked Secure")
	}
	if cookie.Path != "/" {
		t.Errorf("Path = %q; __Host- requires /", cookie.Path)
	}
	if cookie.Domain != "" {
		t.Errorf("Domain = %q; __Host- requires none", cookie.Domain)
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", cookie.SameSite)
	}
}

func TestClearRemovesTheSession(t *testing.T) {
	t.Parallel()

	cookie := newCodec(t).Clear()
	if cookie.Value != "" {
		t.Errorf("Value = %q, want empty", cookie.Value)
	}
	if cookie.MaxAge >= 0 {
		t.Errorf("MaxAge = %d, want negative to delete", cookie.MaxAge)
	}
}

func TestNewCodecRejectsBadKeys(t *testing.T) {
	t.Parallel()

	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		if _, err := NewCodec(make([]byte, n), true); err == nil {
			t.Errorf("NewCodec accepted a %d-byte key", n)
		}
	}
}

// flipLast corrupts the sealed bytes, not the text encoding them. Flipping the
// last base64 character is not the same thing: its low bits often encode
// nothing, so the ciphertext survives unchanged and Open rightly accepts it.
func flipLast(s string) string {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) == 0 {
		return s
	}
	raw[len(raw)-1] ^= 0x01
	return base64.RawURLEncoding.EncodeToString(raw)
}

// A sealed value must have exactly one spelling. Non-strict base64 ignores the
// trailing bits of the final character, so several distinct strings decode to
// the same bytes and present as the same session. It is also what made the
// tamper test above miss: flipping that character often changed nothing.
func TestASealedValueHasOnlyOneSpelling(t *testing.T) {
	t.Parallel()

	c := newCodec(t)

	// Nonce and tag are 28 bytes together, so a payload length divisible by
	// three leaves four spare bits in the last base64 character.
	sealed, err := c.SealRaw(SessionPurpose, []byte("012345678"))
	if err != nil {
		t.Fatalf("SealRaw(): %v", err)
	}

	variant, ok := withSlackBitsSet(sealed)
	if !ok {
		t.Fatal("no spare bits to set, so this test proves nothing")
	}

	if _, err := c.OpenRaw(SessionPurpose, variant); !errors.Is(err, ErrInvalid) {
		t.Errorf("a second spelling of the same value was accepted: err = %v", err)
	}
}

// withSlackBitsSet sets the padding bits in the final base64 character. The
// bytes it decodes to are unchanged, so only a strict decoder notices.
func withSlackBitsSet(s string) (string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", false
	}
	spare, ok := map[int]int{1: 0x0f, 2: 0x03}[len(raw)%3]
	if !ok {
		return "", false
	}

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, s[len(s)-1])
	if last < 0 || last|spare == last {
		return "", false
	}
	return s[:len(s)-1] + string(alphabet[last|spare]), true
}
