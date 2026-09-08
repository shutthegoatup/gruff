package pki

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

// An expired CRL does not merely stop revoking: OpenSSL reports "CRL has
// expired" and refuses the certificate, so every client is rejected. The
// published window must therefore be comfortably wider than however often it
// is rewritten.
func TestCRLOutlivesItsRefreshInterval(t *testing.T) {
	t.Parallel()

	ca, err := Generate("Test Org")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	raw, err := ca.CRL(nil, time.Now())
	if err != nil {
		t.Fatalf("CRL: %v", err)
	}
	block, _ := pem.Decode(raw)
	list, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}

	window := list.NextUpdate.Sub(list.ThisUpdate)

	// The refresher runs hourly. Several missed cycles must still leave the
	// list valid, or a transient failure becomes an outage.
	const refresh = time.Hour
	if window < 4*refresh {
		t.Errorf("validity window %s leaves no room for a missed refresh at %s intervals", window, refresh)
	}
	if time.Until(list.NextUpdate) < 4*refresh {
		t.Errorf("a freshly published list expires in %s", time.Until(list.NextUpdate))
	}
}
