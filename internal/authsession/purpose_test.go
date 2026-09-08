package authsession

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// probeFlow mirrors internal/oidcauth.flow, tags included. The two structs were
// written independently and share three field names by coincidence: "n" is a
// nonce there and a full name here, "r" is the post-login redirect there and
// the caller's roles here, "e" is an expiry in both.
type probeFlow struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"r,omitempty"`
	Expires  int64  `json:"e"`
}

// /auth/login hands a login cookie to anyone who asks, and the value of its
// "r" field comes from the caller's own ?next=. Sealed under the same key with
// nothing to tell the two apart, that ciphertext decrypted cleanly as a session
// and the only thing stopping it being read as one was that Next is a string
// where Roles is a []string - a JSON type mismatch, not a decision.
func TestALoginCookieIsNotASession(t *testing.T) {
	t.Parallel()

	c := newTestCodec(t)

	payload, err := json.Marshal(probeFlow{
		State:    "abc",
		Nonce:    "def",
		Verifier: "ghi",
		Next:     "/",
		Expires:  time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	sealed, err := c.SealRaw(FlowPurpose, payload)
	if err != nil {
		t.Fatalf("SealRaw: %v", err)
	}

	if _, err := c.OpenRaw(SessionPurpose, sealed); !errors.Is(err, ErrInvalid) {
		t.Errorf("a login cookie opened as a session: err = %v, want ErrInvalid", err)
	}
}

// And the other way, so neither is a source of the other.
func TestASessionIsNotALoginCookie(t *testing.T) {
	t.Parallel()

	c := newTestCodec(t)

	sealed, err := c.SealRaw(SessionPurpose, []byte(`{"u":"alice"}`))
	if err != nil {
		t.Fatalf("SealRaw: %v", err)
	}

	if _, err := c.OpenRaw(FlowPurpose, sealed); !errors.Is(err, ErrInvalid) {
		t.Errorf("a session opened as a login cookie: err = %v, want ErrInvalid", err)
	}
}

// The separation has to survive the round trip it exists to protect.
func TestEachPurposeOpensItsOwn(t *testing.T) {
	t.Parallel()

	c := newTestCodec(t)

	for _, purpose := range []Purpose{SessionPurpose, FlowPurpose} {
		t.Run(string(purpose), func(t *testing.T) {
			t.Parallel()

			body := []byte("the payload for " + purpose)
			sealed, err := c.SealRaw(purpose, body)
			if err != nil {
				t.Fatalf("SealRaw: %v", err)
			}

			got, err := c.OpenRaw(purpose, sealed)
			if err != nil {
				t.Fatalf("OpenRaw: %v", err)
			}
			if string(got) != string(body) {
				t.Errorf("round trip = %q, want %q", got, body)
			}
		})
	}
}

// An unknown purpose must not open anything either, so a future caller has to
// name itself rather than inherit someone else's ciphertexts.
func TestAnUnrelatedPurposeOpensNothing(t *testing.T) {
	t.Parallel()

	c := newTestCodec(t)

	sealed, err := c.SealRaw(SessionPurpose, []byte(`{"u":"alice"}`))
	if err != nil {
		t.Fatalf("SealRaw: %v", err)
	}

	if _, err := c.OpenRaw("gruff/something-else/v1", sealed); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

func newTestCodec(t *testing.T) *Codec {
	t.Helper()

	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c, err := NewCodec(key, true)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	return c
}
