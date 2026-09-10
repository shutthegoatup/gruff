package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"time"
)

// ServerValidity is how long an issued server certificate lasts. A VPN server's
// identity is infrastructure, not a user credential, so this is months - but it
// is bounded, so a decommissioned server stops being trusted on its own.
const ServerValidity = 90 * 24 * time.Hour

// IssueServer mints the keypair and certificate an OpenVPN server presents to
// clients.
//
// Clients verify it with remote-cert-tls server, which requires the serverAuth
// usage a client certificate must not have; issuing it here means an operator
// does not have to take the CA key to openssl to get one.
func (ca *CA) IssueServer(commonName string, hosts []string) (Credentials, error) {
	if commonName == "" {
		return Credentials{}, fmt.Errorf("a server certificate needs a common name")
	}

	serial, err := newSerial()
	if err != nil {
		return Credentials{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Credentials{}, fmt.Errorf("generate server key: %w", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	notAfter, err := ca.boundedExpiry(now, ServerValidity)
	if err != nil {
		return Credentials{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		return Credentials{}, fmt.Errorf("sign server certificate: %w", err)
	}
	keyPEM, err := encodeKey(key)
	if err != nil {
		return Credentials{}, err
	}

	return Credentials{
		PrivateKey:  string(keyPEM),
		Certificate: string(encodeCert(der)),
		IssuingCA:   string(encodeCert(ca.cert.Raw)),
		Serial:      serial.String(),
		NotAfter:    notAfter,
	}, nil
}
