// Command gruff serves OpenVPN profiles with embedded, short-lived client
// certificates to users authenticated by an upstream SSO proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shutthegoatup/gruff/internal/authsession"
	"github.com/shutthegoatup/gruff/internal/config"
	"github.com/shutthegoatup/gruff/internal/oidcauth"
	"github.com/shutthegoatup/gruff/internal/openvpn"
	"github.com/shutthegoatup/gruff/internal/pki"
	"github.com/shutthegoatup/gruff/internal/portal"
	"github.com/shutthegoatup/gruff/internal/sshca"
)

const shutdownGrace = 15 * time.Second

// Set via -ldflags at build time; see the Makefile.
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "sign-host" {
		return signHost(os.Args[2:])
	}

	var (
		configPath  = flag.String("config", "configs/conf.yaml", "path to the config file")
		generateCA  = flag.Bool("dev-generate-ca", false, "generate a throwaway CA at startup; for development only")
		caOutputDir = flag.String("dev-ca-dir", "", "directory to write the generated CA to (with -dev-generate-ca)")
		logLevel    = flag.String("log-level", "info", "log level: debug, info, warn or error")
		showVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("gruff %s (%s)\n", version, commit)
		return nil
	}

	log, err := newLogger(*logLevel)
	if err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	ca, err := loadCA(cfg, *generateCA, *caOutputDir, log)
	if err != nil {
		return err
	}

	sshCA, err := loadSSHCA(cfg, *generateCA, *caOutputDir, log)
	if err != nil {
		return err
	}

	if cfg.ConfigdirEnabled {
		if err := openvpn.Write(cfg.ConfigdirPath, cfg.Profiles); err != nil {
			return fmt.Errorf("write OpenVPN config dir: %w", err)
		}
		log.Info("wrote OpenVPN profile files", "path", cfg.ConfigdirPath, "profiles", len(cfg.Profiles))
	}

	auth, err := setupAuth(cfg, log)
	if err != nil {
		return err
	}

	p, err := portal.New(cfg, log, portal.Options{
		Version:      version,
		CA:           ca,
		SSHCA:        sshCA,
		OIDC:         auth.oidc,
		SessionCodec: auth.codec,
	})
	if err != nil {
		return err
	}

	if err := p.PublishRevocations(context.Background()); err != nil {
		return fmt.Errorf("publish revocation list: %w", err)
	}

	// Keep them current: an expired CRL refuses every client, not merely the
	// revoked ones.
	refresh, stopRefresh := context.WithCancel(context.Background())
	defer stopRefresh()
	go p.RefreshRevocations(refresh)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           p.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelError),
	}

	if cfg.MetricsListen != "" {
		metrics := &http.Server{
			Addr:              cfg.MetricsListen,
			Handler:           p.MetricsHandler(),
			ReadHeaderTimeout: 5 * time.Second,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelError),
		}
		go func() {
			log.Info("serving metrics", "addr", cfg.MetricsListen)
			if err := metrics.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics listener stopped", "error", err)
			}
		}()
		defer metrics.Close()
	}

	return serve(srv, log)
}

// serve runs srv until the process is signalled, then drains in-flight requests.
func serve(srv *http.Server, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errs := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
		close(errs)
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}

	log.Info("shutting down", "grace", shutdownGrace)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

// authComponents is whichever of the authentication collaborators the
// configured mode needs. Both are nil in trusted-header mode.
type authComponents struct {
	oidc  *oidcauth.Authenticator
	codec *authsession.Codec
}

// setupAuth builds the authenticator for the configured mode. OIDC discovery
// runs up front so a bad issuer fails startup, not the first sign-in.
func setupAuth(cfg *config.Config, log *slog.Logger) (authComponents, error) {
	if cfg.Auth.Mode != config.AuthOIDC {
		log.Warn("trusted-header mode: Gruff authenticates nobody and must only be reachable through its proxy",
			"listen", cfg.Listen)
		return authComponents{}, nil
	}

	codec, err := authsession.NewCodec(cfg.Auth.SessionKey(), !cfg.Auth.InsecureCookies)
	if err != nil {
		return authComponents{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	auth, err := oidcauth.New(ctx, &cfg.Auth, codec)
	if err != nil {
		return authComponents{}, err
	}

	log.Info("oidc mode", "issuer", cfg.Auth.Issuer, "client_id", cfg.Auth.ClientID,
		"session_lifetime", cfg.Auth.SessionDuration())
	if cfg.Auth.InsecureCookies {
		log.Warn("insecure-cookies is set: session cookies will be sent over plain HTTP")
	}
	return authComponents{oidc: auth, codec: codec}, nil
}

// loadSSHCA resolves the SSH CA, needed only when SSH profiles exist. Missing
// is fatal rather than quietly generated, as with the X.509 CA.
func loadSSHCA(cfg *config.Config, generate bool, outputDir string, log *slog.Logger) (*sshca.CA, error) {
	if len(cfg.SSHProfiles) == 0 {
		return nil, nil
	}

	if cfg.SSHCAPrivateFile != "" {
		if generate {
			return nil, errors.New("-dev-generate-ca conflicts with the configured ssh-ca-private-file")
		}
		return sshca.Load(cfg.SSHCAPrivateFile)
	}

	if !generate {
		return nil, errors.New("ssh profiles are configured but ssh-ca-private-file is not set; pass -dev-generate-ca for development")
	}
	if outputDir == "" {
		return nil, errors.New("-dev-generate-ca requires -dev-ca-dir")
	}

	log.Warn("generating a throwaway SSH CA; hosts trusting the previous key will reject new certificates", "dir", outputDir)
	ca, err := sshca.Generate()
	if err != nil {
		return nil, err
	}
	if err := ca.WriteTo(outputDir); err != nil {
		return nil, err
	}
	log.Info("ssh CA ready", "fingerprint", ca.Fingerprint())
	return ca, nil
}

// loadCA resolves the signing CA. Refusing to start beats silently minting a
// trust anchor nobody meant to create.
func loadCA(cfg *config.Config, generate bool, outputDir string, log *slog.Logger) (*pki.CA, error) {
	if len(cfg.Profiles) == 0 {
		return nil, nil
	}
	if cfg.CACertificateFile != "" {
		if generate {
			return nil, errors.New("-dev-generate-ca conflicts with the configured ca-certificate-file")
		}
		return pki.Load(cfg.CAPrivateFile, cfg.CACertificateFile)
	}

	if !generate {
		return nil, errors.New("no CA configured: set ca-certificate-file and ca-private-file, or pass -dev-generate-ca for development")
	}
	if outputDir == "" {
		return nil, errors.New("-dev-generate-ca requires -dev-ca-dir")
	}

	log.Warn("generating a throwaway CA; every restart invalidates previously issued certificates", "dir", outputDir)
	ca, err := pki.Generate(cfg.Banner)
	if err != nil {
		return nil, err
	}
	if err := ca.WriteTo(outputDir); err != nil {
		return nil, err
	}
	return ca, nil
}

func newLogger(level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("invalid log level %q: %w", level, err)
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l})), nil
}
