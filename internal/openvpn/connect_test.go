package openvpn

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shutthegoatup/gruff/internal/config"
)

// runConnect invokes the generated hook the way OpenVPN does: the profile in
// X509_0_OU, and a path in $1 for the directives it should emit.
func runConnect(t *testing.T, dir, ou string) (string, error) {
	t.Helper()

	out := filepath.Join(t.TempDir(), "client.conf")
	cmd := exec.Command("/bin/sh", filepath.Join(dir, "rules", "connect.sh"), out)
	cmd.Env = append(os.Environ(), "X509_0_OU="+ou)

	if combined, err := cmd.CombinedOutput(); err != nil {
		return string(combined), err
	}
	body, err := os.ReadFile(out)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func writeProfiles(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	if err := Write(dir, []config.Profile{
		{Name: "livedata", Routes: mustNetworks("192.168.1.0/24")},
		{Name: "notlivedata", Routes: mustNetworks("172.16.0.0/16")},
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return dir
}

// The hook is what makes routes work at all: the certificate's common name is
// the user, so client-config-dir cannot select a profile.
func TestConnectScriptEmitsTheProfilesRoutes(t *testing.T) {
	t.Parallel()

	dir := writeProfiles(t)

	body, err := runConnect(t, dir, "livedata")
	if err != nil {
		t.Fatalf("connect.sh failed: %v\n%s", err, body)
	}
	if !strings.Contains(body, `push "route 192.168.1.0 255.255.255.0"`) {
		t.Errorf("wrong routes emitted:\n%s", body)
	}
	if strings.Contains(body, "172.16") {
		t.Errorf("another profile's routes leaked in:\n%s", body)
	}
}

// A non-zero exit refuses the connection, which is the behaviour wanted for
// anything the script does not recognise.
func TestConnectScriptRefuses(t *testing.T) {
	t.Parallel()

	dir := writeProfiles(t)

	for name, ou := range map[string]string{
		"unknown profile": "not-a-profile",
		"no profile":      "",
		"path traversal":  "../../etc/passwd",
		"glob":            "*",
		"command attempt": "livedata; id",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if out, err := runConnect(t, dir, ou); err == nil {
				t.Errorf("connect.sh accepted %q and emitted:\n%s", ou, out)
			}
		})
	}
}

func TestConnectScriptIsValidShellAndExecutable(t *testing.T) {
	t.Parallel()

	dir := writeProfiles(t)
	path := filepath.Join(dir, "rules", "connect.sh")

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Errorf("mode %#o is not executable; OpenVPN has to run it", info.Mode().Perm())
	}

	if out, err := exec.Command("/bin/sh", "-n", path).CombinedOutput(); err != nil {
		t.Errorf("not valid POSIX shell: %v\n%s", err, out)
	}
}
