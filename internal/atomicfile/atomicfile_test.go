package atomicfile_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/shutthegoatup/gruff/internal/atomicfile"
)

// The point of replacing rather than truncating: a write that fails half way
// leaves the previous file in place. Truncating first would have destroyed a
// working CRL and left OpenVPN refusing every client until the next refresh.
func TestFailedWriteLeavesThePreviousFileIntact(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "crl.pem")
	good := "the list that works\n"

	if err := atomicfile.Write(path, 0o644, write(good)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	boom := errors.New("the store went away")
	err := atomicfile.Write(path, 0o644, func(w io.Writer) error {
		io.WriteString(w, "half of a rep")
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Write() error = %v, want it to wrap %v", err, boom)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != good {
		t.Errorf("file = %q, want the previous contents %q", body, good)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("a failed write left %d files behind, want only crl.pem", len(entries))
	}
}

func TestWriteCreatesAFileThatWasNotThere(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "krl")
	if err := atomicfile.Write(path, 0o600, write("body")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// CreateTemp makes 0600 files; a mode wider than that has to be applied.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %#o, want 0600", perm)
	}
}

// A directory that does not exist is a configuration problem, and it must
// surface as one rather than as a silently missing revocation list.
func TestWriteReportsAMissingDirectory(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nope", "crl.pem")
	if err := atomicfile.Write(path, 0o644, write("body")); err == nil {
		t.Error("Write() succeeded into a directory that does not exist")
	}
}

func write(body string) func(io.Writer) error {
	return func(w io.Writer) error {
		_, err := io.WriteString(w, body)
		return err
	}
}
