// Package pki loads a CA and issues short-lived VPN client certificates,
// subject-named for the authenticated user so a credential is attributable.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// File modes for generated material. A private key is readable only by the
// process that owns it.
const (
	keyFileMode  os.FileMode = 0o600
	certFileMode os.FileMode = 0o644
	dirMode      os.FileMode = 0o700
)

const caValidity = 10 * 365 * 24 * time.Hour

// signer is the subset of a private key needed to sign certificates.
type signer interface {
	crypto.Signer
}

// CA signs client certificates.
type CA struct {
	key  signer
	cert *x509.Certificate
}

// Credentials is an issued client keypair together with its issuing CA.
type Credentials struct {
	PrivateKey  string
	Certificate string
	IssuingCA   string
	Serial      string
	NotAfter    time.Time
}

// Load reads a CA keypair from disk.
func Load(keyPath, certPath string) (*CA, error) {
	cert, err := loadCertificate(certPath)
	if err != nil {
		return nil, err
	}
	key, err := loadPrivateKey(keyPath)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("%s: certificate is not a CA", certPath)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("%s: CA certificate lacks the certSign key usage", certPath)
	}
	// Gruff signs the revocation list with this key too, and a CRL from a CA
	// without crlSign is refused by the servers that read it.
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, fmt.Errorf("%s: CA certificate lacks the crlSign key usage, so its revocation list would be rejected", certPath)
	}
	// A dead CA issues certificates nothing will accept: the portal works, the
	// download works, and every connection fails on a chain that cannot be
	// verified. Say so at startup instead.
	now := time.Now()
	if now.After(cert.NotAfter) {
		return nil, fmt.Errorf("%s: CA expired on %s", certPath, cert.NotAfter.Format(time.RFC3339))
	}
	if now.Before(cert.NotBefore) {
		return nil, fmt.Errorf("%s: CA is not valid until %s", certPath, cert.NotBefore.Format(time.RFC3339))
	}
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return nil, fmt.Errorf("%s: %T cannot be compared to its certificate", keyPath, key.Public())
	}
	if !pub.Equal(cert.PublicKey) {
		return nil, errors.New("CA private key does not match its certificate")
	}
	return &CA{key: key, cert: cert}, nil
}

// Generate creates a new self-signed CA. It is a development convenience: a
// deployment should be given a CA it already trusts.
func Generate(organization string) (*CA, error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{organization}, CommonName: organization + " VPN CA"},
		NotBefore:             now,
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated CA certificate: %w", err)
	}
	return &CA{key: key, cert: cert}, nil
}

// Issue signs a client certificate for user in profile, valid for d.
func (ca *CA) Issue(user, profile string, d time.Duration) (Credentials, error) {
	serial, err := newSerial()
	if err != nil {
		return Credentials{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Credentials{}, fmt.Errorf("generate client key: %w", err)
	}

	// x509 encodes validity with second granularity, so truncate here rather
	// than let the reported expiry drift from the certificate's own.
	now := time.Now().UTC().Truncate(time.Second)
	notAfter, err := ca.boundedExpiry(now, d)
	if err != nil {
		return Credentials{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         user,
			OrganizationalUnit: []string{profile},
		},
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		return Credentials{}, fmt.Errorf("sign client certificate: %w", err)
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

// boundedExpiry is when a certificate issued now for d should run out.
//
// A certificate cannot usefully outlive the CA that signed it: the chain stops
// verifying the moment the issuer lapses, so the holder is left with a
// credential that claims hours it does not have. Shortening it is honest - the
// portal shows the real expiry - and it is what a renewal would do anyway.
func (ca *CA) boundedExpiry(now time.Time, d time.Duration) (time.Time, error) {
	// Load refuses a lapsed CA, but a process outlives its startup.
	if !now.Before(ca.cert.NotAfter) {
		return time.Time{}, fmt.Errorf("the CA expired on %s and can issue nothing",
			ca.cert.NotAfter.Format(time.RFC3339))
	}

	notAfter := now.Add(d)
	if issuer := ca.cert.NotAfter.UTC().Truncate(time.Second); notAfter.After(issuer) {
		return issuer, nil
	}
	return notAfter, nil
}

// CertificatePEM returns the CA certificate, for writing out or pinning.
func (ca *CA) CertificatePEM() []byte { return encodeCert(ca.cert.Raw) }

// WriteTo persists the CA keypair under dir as ca/key.pem and ca/cert.pem.
func (ca *CA) WriteTo(dir string) error {
	caDir := filepath.Join(dir, "ca")
	if err := os.MkdirAll(caDir, dirMode); err != nil {
		return fmt.Errorf("create %s: %w", caDir, err)
	}
	keyPEM, err := encodeKey(ca.key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(caDir, "key.pem"), keyPEM, keyFileMode); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(caDir, "cert.pem"), ca.CertificatePEM(), certFileMode); err != nil {
		return fmt.Errorf("write CA certificate: %w", err)
	}
	return nil
}

func newSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}

func encodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func encodeKey(key crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func loadCertificate(path string) (*x509.Certificate, error) {
	block, err := readPEM(path, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return cert, nil
}

// loadPrivateKey accepts PKCS#8 and the legacy SEC 1 / PKCS#1 encodings that
// older CA material is likely to be stored in.
func loadPrivateKey(path string) (signer, error) {
	block, err := readPEM(path, "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY")
	if err != nil {
		return nil, err
	}

	var key crypto.PrivateKey
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	s, ok := key.(signer)
	if !ok {
		return nil, fmt.Errorf("%s: %T cannot sign certificates", path, key)
	}
	return s, nil
}

func readPEM(path string, allowed ...string) (*pem.Block, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block found", path)
	}
	for _, t := range allowed {
		if block.Type == t {
			return block, nil
		}
	}
	return nil, fmt.Errorf("%s: unexpected PEM block %q", path, block.Type)
}
