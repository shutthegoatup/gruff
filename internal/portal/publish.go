package portal

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/shutthegoatup/gruff/internal/pki"
)

const crlFileMode os.FileMode = 0o644

// RefreshInterval is how often the lists are rewritten. Well inside
// crlValidity, so a missed cycle is survivable rather than an outage.
const RefreshInterval = time.Hour

// PublishRevocations writes the current lists, at startup and on a timer, so a
// server is never left with a missing or an expired one.
func (p *Portal) PublishRevocations(ctx context.Context) error {
	return p.publishRevocations(ctx)
}

// RefreshRevocations rewrites the lists until ctx is cancelled.
//
// Without this the CRL is only rewritten when something is revoked, and every
// client is refused once it passes nextUpdate.
func (p *Portal) RefreshRevocations(ctx context.Context) {
	if !p.cfg.ConfigdirEnabled {
		return
	}

	ticker := time.NewTicker(RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.publishRevocations(ctx); err != nil {
				p.log.ErrorContext(ctx, "refresh revocation lists", "error", err)
			}
		}
	}
}

// publishRevocations writes the current CRL where the OpenVPN server reads it.
//
// It is rewritten on every revocation rather than served from an endpoint,
// because that is the mechanism already in place for the ccd and rules files
// and it needs no network path from the VPN server back to Gruff.
func (p *Portal) publishRevocations(ctx context.Context) error {
	if !p.cfg.ConfigdirEnabled {
		return nil
	}

	if p.ca != nil {
		crl, err := p.currentCRL(ctx)
		if err != nil {
			return err
		}
		if err := p.writeList("crl.pem", crl); err != nil {
			return err
		}
	}

	if p.sshCA != nil {
		krl, err := p.currentKRL(ctx)
		if err != nil {
			return err
		}
		if err := p.writeList("krl", krl); err != nil {
			return err
		}
	}
	return nil
}

func (p *Portal) writeList(name string, body []byte) error {
	path := filepath.Join(p.cfg.ConfigdirPath, name)
	if err := os.WriteFile(path, body, crlFileMode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// currentKRL builds the SSH revocation list from the store.
func (p *Portal) currentKRL(ctx context.Context) ([]byte, error) {
	var serials []uint64

	if revoker, ok := p.sessions.(Revoker); ok {
		entries, err := revoker.Revocations(ctx, KindSSH)
		if err != nil {
			return nil, fmt.Errorf("read revocations: %w", err)
		}
		for _, e := range entries {
			serial, err := strconv.ParseUint(e.Serial, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("ssh serial %q: %w", e.Serial, err)
			}
			serials = append(serials, serial)
		}
	}

	return p.sshCA.KRL(serials, time.Now())
}

// currentCRL builds the list from whatever the store currently holds.
func (p *Portal) currentCRL(ctx context.Context) ([]byte, error) {
	var revoked []pki.Revoked

	if revoker, ok := p.sessions.(Revoker); ok {
		entries, err := revoker.Revocations(ctx, KindVPN)
		if err != nil {
			return nil, fmt.Errorf("read revocations: %w", err)
		}
		for _, e := range entries {
			revoked = append(revoked, pki.Revoked{Serial: e.Serial, At: e.At})
		}
	}

	return p.ca.CRL(revoked, time.Now())
}
