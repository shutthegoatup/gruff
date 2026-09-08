package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/shutthegoatup/gruff/internal/config"
	"github.com/shutthegoatup/gruff/internal/sshca"
)

// signHost signs a host's public key, printing the certificate to stdout.
//
// This is a subcommand rather than a page because host keys are provisioned by
// configuration management, not by a person pasting into a form. It runs where
// the CA key already is, which is the same trust boundary as the portal itself.
//
//	gruff sign-host -config /etc/gruff.yml -hostnames a.example.com,10.0.0.5 \
//	  < /etc/ssh/ssh_host_ed25519_key.pub > /etc/ssh/ssh_host_ed25519_key-cert.pub
func signHost(args []string) error {
	fs := flag.NewFlagSet("sign-host", flag.ContinueOnError)
	var (
		configPath = fs.String("config", "configs/conf.yaml", "path to the config file")
		keyPath    = fs.String("key", "-", "host public key to sign; - reads stdin")
		hostnames  = fs.String("hostnames", "", "comma-separated names the certificate is valid for")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	principals := splitList(*hostnames)
	if len(principals) == 0 {
		return errors.New("sign-host requires -hostnames")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.SSHCAPrivateFile == "" {
		return errors.New("ssh-ca-private-file is not configured, so there is no CA to sign with")
	}
	ca, err := sshca.Load(cfg.SSHCAPrivateFile)
	if err != nil {
		return err
	}

	pub, err := readKey(*keyPath)
	if err != nil {
		return err
	}

	creds, err := ca.SignHost(string(pub), principals, time.Now())
	if err != nil {
		return err
	}

	// The certificate goes to stdout so it can be redirected into place; the
	// note goes to stderr so it does not end up in the file.
	fmt.Fprintln(os.Stdout, creds.Certificate)
	fmt.Fprintf(os.Stderr, "signed %s, expires %s\n",
		strings.Join(creds.Principals, ", "), creds.NotAfter.Format(time.RFC3339))
	return nil
}

func readKey(path string) ([]byte, error) {
	if path == "-" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read host key from stdin: %w", err)
		}
		return b, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read host key: %w", err)
	}
	return b, nil
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
