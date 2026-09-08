// Package atomicfile replaces a file in one step, for files something else is
// reading while Gruff writes them.
//
// The OpenVPN server reads crl.pem and executes rules/connect.sh on every
// client connection, and Gruff rewrites both - the CRL hourly and on every
// revocation. Truncating in place leaves a window where a reader sees a partial
// file, and the failures are quiet: a half-written CRL refuses a client that
// should have connected, and a truncated connect.sh that happens to be empty
// exits zero, so the client is admitted with none of its routes.
package atomicfile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Write renders body into path, replacing whatever is there in a single rename.
// A reader sees either the previous file or the new one, never a mixture.
//
// Concurrent writers are safe: each builds its own temporary file and the last
// rename wins. Every writer here renders a complete snapshot, so whichever
// lands is coherent.
func Write(path string, mode os.FileMode, render func(io.Writer) error) error {
	dir := filepath.Dir(path)

	// Same directory, so the rename cannot cross a filesystem. Dot-prefixed so
	// a half-built file is not mistaken for one of the generated ones.
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create a temporary file beside %s: %w", path, err)
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("set mode on %s: %w", tmp.Name(), err)
	}
	if err := render(tmp); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	// Before the rename, or a crash can leave the name pointing at a file whose
	// contents never reached the disk.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}

	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return syncDir(dir)
}

// syncDir makes the rename itself durable. Without it the file survives a crash
// but the name may still point at the old one.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open %s: %w", dir, err)
	}
	defer d.Close()

	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	return nil
}
