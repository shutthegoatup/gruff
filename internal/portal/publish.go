package portal

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/shutthegoatup/gruff/internal/pki"
)

const crlFileMode os.FileMode = 0o644

// PublishRevocations writes the current CRL at startup, so a server is never
// left with a missing list - which is not the same as an empty one.
func (p *Portal) PublishRevocations(ctx context.Context) error {
	return p.publishRevocations(ctx)
}

// publishRevocations writes the current CRL where the OpenVPN server reads it.
//
// It is rewritten on every revocation rather than served from an endpoint,
// because that is the mechanism already in place for the ccd and rules files
// and it needs no network path from the VPN server back to Gruff.
func (p *Portal) publishRevocations(ctx context.Context) error {
	if !p.cfg.ConfigdirEnabled || p.ca == nil {
		return nil
	}

	crl, err := p.currentCRL(ctx)
	if err != nil {
		return err
	}

	path := filepath.Join(p.cfg.ConfigdirPath, "crl.pem")
	if err := os.WriteFile(path, crl, crlFileMode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
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
