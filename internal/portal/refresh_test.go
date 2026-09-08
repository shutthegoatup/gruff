package portal

import (
	"context"
	"os"
	"path/filepath"
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
