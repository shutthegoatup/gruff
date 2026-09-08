package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/shutthegoatup/gruff/internal/config"
	"github.com/shutthegoatup/gruff/internal/pki"
)

// signServer issues the certificate an OpenVPN server presents to clients.
//
// Clients verify it with remote-cert-tls server, which needs the serverAuth
// usage a client certificate must not carry, so it cannot simply be issued
// through the portal. Without this an operator has to take the CA key to
// openssl, which is the one thing a CA exists to avoid.
//
//	gruff sign-server -config /etc/gruff.yml -cn vpn.example.com -out /etc/openvpn
func signServer(args []string) error {
	fs := flag.NewFlagSet("sign-server", flag.ContinueOnError)
	var (
		configPath = fs.String("config", "configs/conf.yaml", "path to the config file")
		commonName = fs.String("cn", "", "common name for the server certificate")
		hosts      = fs.String("hosts", "", "comma-separated names and addresses clients reach it on")
		outDir     = fs.String("out", "", "directory to write cert.pem and key.pem into")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *commonName == "" {
		return errors.New("sign-server requires -cn")
	}
	if *outDir == "" {
		return errors.New("sign-server requires -out")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.CACertificateFile == "" {
		return errors.New("no CA is configured to sign with")
	}
	ca, err := pki.Load(cfg.CAPrivateFile, cfg.CACertificateFile)
	if err != nil {
		return err
	}

	creds, err := ca.IssueServer(*commonName, splitList(*hosts))
	if err != nil {
		return err
	}

	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", *outDir, err)
	}
	certPath := filepath.Join(*outDir, "cert.pem")
	keyPath := filepath.Join(*outDir, "key.pem")

	if err := os.WriteFile(certPath, []byte(creds.Certificate), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", certPath, err)
	}
	if err := os.WriteFile(keyPath, []byte(creds.PrivateKey), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", keyPath, err)
	}

	fmt.Fprintf(os.Stderr, "wrote %s and %s, expires %s\n",
		certPath, keyPath, creds.NotAfter.Format(time.RFC3339))
	return nil
}
