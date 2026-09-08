package sshca

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// HostCertValidity is how long a host certificate lasts. Host keys are not
// rotated on the cadence user credentials are, so this is months rather than
// hours - but it is bounded, so a decommissioned host stops being trusted
// without anyone having to remember it.
const HostCertValidity = 90 * 24 * time.Hour

// HostCredentials is a signed host certificate.
type HostCredentials struct {
	Certificate string
	Serial      uint64
	Principals  []string
	NotAfter    time.Time
}

// SignHost signs a host's existing public key.
//
// Unlike a user credential, the key is the host's own: sshd already has one,
// and there is no reason for Gruff to see its private half.
func (ca *CA) SignHost(authorizedKey string, principals []string, now time.Time) (HostCredentials, error) {
	if len(principals) == 0 {
		return HostCredentials{}, fmt.Errorf("a host certificate needs at least one hostname")
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return HostCredentials{}, fmt.Errorf("parse host public key: %w", err)
	}
	if _, isCert := pub.(*ssh.Certificate); isCert {
		return HostCredentials{}, fmt.Errorf("that is a certificate, not a host public key")
	}

	serial, err := newSerial()
	if err != nil {
		return HostCredentials{}, err
	}

	now = now.UTC().Truncate(time.Second)
	notAfter := now.Add(HostCertValidity)

	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          serial,
		CertType:        ssh.HostCert,
		KeyId:           strings.Join(principals, ","),
		ValidPrincipals: principals,
		ValidAfter:      uint64(now.Add(-time.Minute).Unix()),
		ValidBefore:     uint64(notAfter.Unix()),
	}
	if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
		return HostCredentials{}, fmt.Errorf("sign host certificate: %w", err)
	}

	return HostCredentials{
		Certificate: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))),
		Serial:      serial,
		Principals:  principals,
		NotAfter:    notAfter,
	}, nil
}

// KnownHostsLine is the client-side half: it tells ssh to trust any host
// certificate this CA signed for the given patterns, instead of asking the user
// to confirm a fingerprint they have no way to check.
func (ca *CA) KnownHostsLine(patterns []string) string {
	if len(patterns) == 0 {
		patterns = []string{"*"}
	}
	return fmt.Sprintf("@cert-authority %s %s", strings.Join(patterns, ","), ca.PublicKey())
}
