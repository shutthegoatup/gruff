package pki

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// crlValidity is how long a published list stays current.
//
// This is not a fail-open knob: OpenSSL rejects every certificate once a CRL
// passes nextUpdate ("CRL has expired"), so an under-refreshed list takes the
// whole VPN down rather than merely missing a revocation. The window is
// therefore comfortably wider than the refresh interval, which is what keeps
// it current.
const crlValidity = 24 * time.Hour

// Revoked is a certificate that should no longer be honoured, until the moment
// it would have expired anyway.
type Revoked struct {
	Serial string
	At     time.Time
}

// CRL builds a PEM revocation list for OpenVPN's crl-verify.
//
// An empty list is still worth publishing: it is what tells a server the list
// is current rather than missing.
func (ca *CA) CRL(revoked []Revoked, now time.Time) ([]byte, error) {
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, r := range revoked {
		serial, ok := new(big.Int).SetString(r.Serial, 10)
		if !ok {
			return nil, fmt.Errorf("serial %q is not a decimal integer", r.Serial)
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: r.At.UTC().Truncate(time.Second),
		})
	}

	number, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return nil, fmt.Errorf("generate CRL number: %w", err)
	}

	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		RevokedCertificateEntries: entries,
		Number:                    number,
		ThisUpdate:                now.UTC().Truncate(time.Second),
		NextUpdate:                now.UTC().Truncate(time.Second).Add(crlValidity),
	}, ca.cert, ca.key)
	if err != nil {
		return nil, fmt.Errorf("create revocation list: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil
}
