package app

import (
	"log"
	"net/http"
	"time"

	"github.com/secureweb/vpn-portal/internal/pkg/pki"
)

var c conf
var s sessions
var ca pki.CertificateAuthority

// Run starts the app
func Run() {

	setupVars()

	c.getConf(config)
	c.validate()

	if err := c.writeRules(); err != nil {
		log.Fatal(err)
	}

	if c.CAPrivateFile == "" && c.CACertificateFile == "" {
		log.Printf("Config Warning: No CA specified, creating one...")
		ca.CreateCertificateAuthority()
		err := ca.OutputCertificates("/tmp/tls/")
		if err != nil {
			log.Fatal(err)
		}
	} else {

		if c.CAPrivateFile == "" {
			log.Fatal("Config Error: CAPrivateFile isn't set but CACertificateFile is.  Both must be nil to auto-generate CA.")
		}
		if c.CACertificateFile == "" {
			log.Fatal("Config Error: CACertificateFile isn't set but CAPrivateFile is.  Both must be nil to auto-generate CA.")
		}

		ca.LoadCertificateAuthority(c.CAPrivateFile, c.CACertificateFile)
	}

	srv := &http.Server{
		Handler:      router(),
		Addr:         c.Listen,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		IdleTimeout:  time.Second * 60,
	}

	log.Printf("Config Info: Starting webserver on %s", c.Listen)
	log.Fatal(srv.ListenAndServe())
}
