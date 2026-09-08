package portal

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// The lists must be rewritten on a timer, not only when something is revoked:
// an expired CRL refuses every client, not merely the revoked ones.
func TestRefreshRewritesTheLists(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		p, _ := buildTestPortal(t, 0)
		dir := t.TempDir()
		p.cfg.ConfigdirEnabled = true
		p.cfg.ConfigdirPath = dir

		if err := p.PublishRevocations(context.Background()); err != nil {
			t.Fatalf("PublishRevocations: %v", err)
		}
		crl := filepath.Join(dir, "crl.pem")
		before := readFile(t, crl)

		ctx, cancel := context.WithCancel(context.Background())
		go p.RefreshRevocations(ctx)

		time.Sleep(RefreshInterval + time.Minute)
		cancel()
		synctest.Wait()

		// The CRL number is random per issue, so a rewrite changes the bytes.
		if after := readFile(t, crl); after == before {
			t.Error("the CRL was not rewritten after a refresh interval")
		}
	})
}

// A refresher started without configdir must not spin.
func TestRefreshIsInertWithoutConfigdir(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		p, _ := buildTestPortal(t, 0)
		p.cfg.ConfigdirEnabled = false

		done := make(chan struct{})
		go func() {
			p.RefreshRevocations(context.Background())
			close(done)
		}()

		synctest.Wait()
		select {
		case <-done:
		default:
			t.Error("RefreshRevocations should return immediately without configdir")
		}
	})
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// The hourly refresher and a revocation both publish, so two writers can hit
// crl.pem at once - and OpenVPN re-reads it on every connection. A reader must
// always find a CRL it can parse, or a client that should have connected is
// refused for the width of a write.
func TestPublishedCRLIsAlwaysParseable(t *testing.T) {
	t.Parallel()

	p, _ := buildTestPortal(t, 0)
	dir := t.TempDir()
	p.cfg.ConfigdirEnabled = true
	p.cfg.ConfigdirPath = dir

	ctx := t.Context()
	if err := p.PublishRevocations(ctx); err != nil {
		t.Fatalf("PublishRevocations: %v", err)
	}
	crl := filepath.Join(dir, "crl.pem")

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if err := p.publishRevocations(ctx); err != nil {
						return
					}
				}
			}
		}()
	}

	// Stands in for OpenVPN checking a connecting client against the list.
	var reads int
	for range 500 {
		body, err := os.ReadFile(crl)
		if err != nil {
			t.Errorf("the CRL disappeared mid-rewrite: %v", err)
			break
		}
		block, _ := pem.Decode(body)
		if block == nil {
			t.Errorf("read %d: not PEM at all, %d bytes", reads, len(body))
			break
		}
		if _, err := x509.ParseRevocationList(block.Bytes); err != nil {
			t.Errorf("read %d: OpenVPN would reject this list: %v", reads, err)
			break
		}
		reads++
	}
	close(stop)
	wg.Wait()

	if reads == 0 {
		t.Fatal("never managed to read the list")
	}
}
