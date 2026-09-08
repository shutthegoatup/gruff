// Package sshca issues short-lived OpenSSH user certificates.
//
// Gruff owns the certificate authority and mints the keypair itself: the
// credential is deliberately ephemeral, so there is no long-lived user key to
// enrol and nothing for a user to upload. The private key exists only for the
// life of the response that carries it.
package sshca

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	keyFileMode  os.FileMode = 0o600
	certFileMode os.FileMode = 0o644
	dirMode      os.FileMode = 0o700
)

// CA signs OpenSSH user certificates.
type CA struct {
	signer ssh.Signer
	// key is retained so the CA can be written back out; ssh.Signer does not
	// expose the key it wraps.
	key crypto.PrivateKey
}

// Credentials is an issued keypair with its certificate.
type Credentials struct {
	// PrivateKey is an OpenSSH-format private key.
	PrivateKey string
	// Certificate is an authorized_keys-style certificate line.
	Certificate string
	// Serial identifies the certificate in the sshd log.
	Serial uint64
	// KeyID is what sshd records as the certificate identity.
	KeyID      string
	Principals []string
	NotAfter   time.Time
}

// Load reads an OpenSSH CA private key from disk.
func Load(path string) (*CA, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read SSH CA key: %w", err)
	}
	key, err := ssh.ParseRawPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("parse SSH CA key %s: %w", path, err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("build SSH CA signer from %s: %w", path, err)
	}
	return &CA{signer: signer, key: key}, nil
}

// Generate creates a new ed25519 CA. It is a development convenience: a
// deployment should be given a CA whose public key its hosts already trust.
func Generate() (*CA, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate SSH CA key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("build SSH CA signer: %w", err)
	}
	return &CA{signer: signer, key: priv}, nil
}

// PublicKey returns the CA's public key in authorized_keys form. This is the
// value a host trusts via TrustedUserCAKeys.
func (ca *CA) PublicKey() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca.signer.PublicKey())))
}

// Fingerprint is the SHA256 fingerprint of the CA public key.
func (ca *CA) Fingerprint() string {
	return ssh.FingerprintSHA256(ca.signer.PublicKey())
}

// Issue mints a keypair and signs a user certificate valid for d.
//
// The key ID carries the authenticated username and profile so that every sshd
// authentication line is attributable to a person without consulting Gruff.
func (ca *CA) Issue(user, profile string, principals []string, d time.Duration, extensions []string) (Credentials, error) {
	if len(principals) == 0 {
		return Credentials{}, fmt.Errorf("profile %q has no principals", profile)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Credentials{}, fmt.Errorf("generate client key: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return Credentials{}, fmt.Errorf("wrap client key: %w", err)
	}

	serial, err := newSerial()
	if err != nil {
		return Credentials{}, err
	}

	// Second granularity, matching how the certificate encodes validity.
	now := time.Now().UTC().Truncate(time.Second)
	notAfter := now.Add(d)
	keyID := fmt.Sprintf("%s@%s", user, profile)

	cert := &ssh.Certificate{
		Key:             sshPub,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           keyID,
		ValidPrincipals: principals,
		// A minute of leeway absorbs clock skew between Gruff and the host.
		ValidAfter:  uint64(now.Add(-time.Minute).Unix()),
		ValidBefore: uint64(notAfter.Unix()),
		Permissions: ssh.Permissions{
			Extensions: extensionMap(extensions),
		},
	}

	if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
		return Credentials{}, fmt.Errorf("sign SSH certificate: %w", err)
	}

	keyPEM, err := marshalPrivateKey(priv, keyID)
	if err != nil {
		return Credentials{}, err
	}

	return Credentials{
		PrivateKey:  string(keyPEM),
		Certificate: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))),
		Serial:      serial,
		KeyID:       keyID,
		Principals:  principals,
		NotAfter:    notAfter,
	}, nil
}

// WriteTo persists the CA keypair under dir as ssh/ca and ssh/ca.pub.
func (ca *CA) WriteTo(dir string) error {
	sshDir := filepath.Join(dir, "ssh")
	if err := os.MkdirAll(sshDir, dirMode); err != nil {
		return fmt.Errorf("create %s: %w", sshDir, err)
	}

	keyPEM, err := marshalPrivateKey(ca.key, "gruff-ssh-ca")
	if err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(sshDir, "ca"), keyPEM, keyFileMode); err != nil {
		return fmt.Errorf("write SSH CA key: %w", err)
	}
	pub := ca.PublicKey() + "\n"
	if err := os.WriteFile(filepath.Join(sshDir, "ca.pub"), []byte(pub), certFileMode); err != nil {
		return fmt.Errorf("write SSH CA public key: %w", err)
	}
	return nil
}

func marshalPrivateKey(key crypto.PrivateKey, comment string) ([]byte, error) {
	block, err := ssh.MarshalPrivateKey(key, comment)
	if err != nil {
		return nil, fmt.Errorf("marshal SSH private key: %w", err)
	}
	return pem.EncodeToMemory(block), nil
}

// extensionMap turns the configured extension names into the empty-valued map
// OpenSSH expects. An extension sshd does not recognise is ignored by it, but
// the configuration layer restricts these to a known set regardless.
func extensionMap(names []string) map[string]string {
	if len(names) == 0 {
		return nil
	}
	m := make(map[string]string, len(names))
	for _, n := range names {
		m[n] = ""
	}
	return m
}

func newSerial() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("generate serial: %w", err)
	}
	// Clear the top bit: OpenSSH prints serials as signed in some tooling.
	return binary.BigEndian.Uint64(b[:]) >> 1, nil
}
