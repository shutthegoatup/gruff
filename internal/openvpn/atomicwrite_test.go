package openvpn

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The OpenVPN server executes rules/connect.sh on every client connection, and
// Gruff rewrites it whenever the config is republished. Truncating in place
// left a wide window - measured at four reads in five during a rewrite - where
// a connecting client got a partial file. That fails quietly in the worst
// direction: a truncated script that happens to be empty exits zero, so
// OpenVPN admits the client with none of its routes pushed.
func TestGeneratedFilesAreNeverSeenHalfWritten(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "connect.sh")

	body := strings.Repeat("# a line of the generated script\n", 200)
	render := func(w io.Writer) error {
		_, err := io.WriteString(w, body)
		return err
	}
	if err := writeFile(path, render); err != nil {
		t.Fatalf("writeFile: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				if err := writeFile(path, render); err != nil {
					return
				}
			}
		}
	}()

	var reads, torn int
	for range 20000 {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("the file disappeared mid-rewrite: %v", err)
			break
		}
		reads++
		if string(got) != body {
			torn++
		}
	}
	close(stop)
	wg.Wait()

	if torn > 0 {
		t.Errorf("%d of %d reads saw something other than the whole script", torn, reads)
	}
}

// The replacement must not leave its working files behind, or the next
// republish scatters them through the directory OpenVPN reads.
func TestReplacementLeavesNothingBehind(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "connect.sh")
	render := func(w io.Writer) error {
		_, err := io.WriteString(w, "#!/bin/sh\n")
		return err
	}

	for range 5 {
		if err := writeFile(path, render); err != nil {
			t.Fatalf("writeFile: %v", err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "connect.sh" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("directory holds %v, want only connect.sh", names)
	}
}

// The mode has to survive the replacement: OpenVPN execs this one.
func TestReplacementKeepsTheMode(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "connect.sh")
	if err := writeFileMode(path, func(w io.Writer) error {
		_, err := io.WriteString(w, "#!/bin/sh\n")
		return err
	}, 0o750); err != nil {
		t.Fatalf("writeFileMode: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o750 {
		t.Errorf("mode = %#o, want 0750: OpenVPN has to be able to run it", perm)
	}
}
