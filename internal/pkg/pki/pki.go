package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

type CertificateAuthority struct {
	privateKey crypto.PrivateKey
	publicKey  *x509.Certificate
}

// Keys holds the private keys
type Keys struct {
	PrivateKey string
	PublicKey  string
	IssuingCA  string
}

type Server struct {
	PrivateKey string
	PublicKey  string
	DH string
}

func (ca *CertificateAuthority) CreateCertificateAuthority() error {

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{"ORGANIZATION_NAME"},
			Country:       []string{"COUNTRY_CODE"},
			Province:      []string{"PROVINCE"},
			Locality:      []string{"CITY"},
			StreetAddress: []string{"ADDRESS"},
			PostalCode:    []string{"POSTAL_CODE"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	priv, err := genPrivateKey("P256")
	if err != nil {
		return err
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, publicKey(priv), priv)
	if err != nil {
		return err
	}
	ca.publicKey, err = x509.ParseCertificate(cert)
	if err != nil {
		return err
	}
	ca.privateKey = priv
	
	return err
}

// SetupCA imports the CA files and set them up in golang
func (ca *CertificateAuthority) LoadCertificateAuthority(privateKeyPath string, publicKeyPath string) error {

	caBuf, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return err
	}
	publicKeyPem, _ := pem.Decode(caBuf)

	ca.publicKey, err = x509.ParseCertificate(publicKeyPem.Bytes)
	if err != nil {
		return err
	}

	caPrivBuf, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return err
	}
	caPrivBufDer, _ := pem.Decode(caPrivBuf)
	if err != nil {
		return err
	}

	//
	// Not sure on a better way to detect EC vs RSA.
	//
	ca.privateKey, err = x509.ParsePKCS1PrivateKey(caPrivBufDer.Bytes)
	if err != nil {
		ca.privateKey, err = x509.ParseECPrivateKey(caPrivBufDer.Bytes)
	}
	if err != nil {
		return err
	}

	return err
}

// GenCertificate generates signed client certificates.
func (ca *CertificateAuthority) GenerateCertificate(issueTime time.Time, expireTime time.Time, commonName string) (Keys, error) {

	var k Keys

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return k, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             issueTime,
		NotAfter:              expireTime,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	priv, err := genPrivateKey("P256")
	if err != nil {
		return k, err
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, ca.publicKey, publicKey(priv), ca.privateKey)
	if err != nil {
		return k, err
	}

	k.PrivateKey = string(pem.EncodeToMemory(pemBlockForKey(priv)))
	k.PublicKey = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
	k.IssuingCA = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.publicKey.Raw}))

	return k, err
}


func (ca *CertificateAuthority) OutputCertificates(path string) error {

	// The CA cert/key are written into path/ca and the server cert/key into
	// path/openvpn; make sure those directories exist before writing.
	if err := os.MkdirAll(path+"/ca", 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(path+"/openvpn", 0755); err != nil {
		return err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "openvpn.secureweb.ltd",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	priv, err := genPrivateKey("P256")
	if err != nil {
		return err
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, ca.publicKey, publicKey(priv), ca.privateKey)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(path + "/openvpn/key.pem", pem.EncodeToMemory(pemBlockForKey(priv)), 0644 )
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path + "/openvpn/cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), 0644)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path + "/ca/key.pem", pem.EncodeToMemory(pemBlockForKey(ca.privateKey)) , 0644)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path + "/ca/cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.publicKey.Raw}) , 0644)
	return err

}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func genPrivateKey(keyType string) (crypto.PrivateKey, error) {
	var priv crypto.PrivateKey
	var err error

	switch keyType {
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "RSA4096":
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
	case "RSA2048":
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		err = errors.New("Unknown key type: " + keyType)
	}
	return priv, err
}