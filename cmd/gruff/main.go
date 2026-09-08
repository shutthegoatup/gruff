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

	"github.com/shutthegoatup/gruff/internal/config"
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

	p, err := portal.New(cfg, ca, sshCA, log)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           p.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelError),
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

// loadSSHCA resolves the SSH certificate authority, which is only needed when
// SSH profiles are configured. As with the X.509 CA, a missing one is fatal
// rather than quietly generated.
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

// loadCA resolves the signing CA. The portal refuses to start without one:
// silently minting a trust anchor would leave an operator believing they had
// configured the CA they meant to.
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
