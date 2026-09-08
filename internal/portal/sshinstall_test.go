package portal

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The installer is the deliverable, so it is checked by actually running it in
// a throwaway HOME and inspecting what lands on disk - not by matching strings.
func TestInstallerScriptInstallsTheCredential(t *testing.T) {
	t.Parallel()

	script := issueInstaller(t, "bastion", "ssh-bastion")
	home := runInstaller(t, script)

	dir := filepath.Join(home, ".ssh", "gruff", "bastion")

	key := filepath.Join(dir, "id_ed25519")
	info, err := os.Stat(key)
	if err != nil {
		t.Fatalf("private key was not installed: %v", err)
	}
	// The whole reason this is a script rather than loose files: ssh refuses a
	// key anyone else can read.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("private key mode = %#o, want 0600", perm)
	}

	body, err := os.ReadFile(key)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if !strings.Contains(string(body), "OPENSSH PRIVATE KEY") {
		t.Errorf("installed key is not an OpenSSH key:\n%s", body)
	}

	cert, err := os.ReadFile(filepath.Join(dir, "id_ed25519-cert.pub"))
	if err != nil {
		t.Fatalf("certificate was not installed: %v", err)
	}
	if !strings.HasPrefix(string(cert), "ssh-ed25519-cert-v01@openssh.com ") {
		t.Errorf("installed certificate has the wrong form:\n%s", cert)
	}

	conf, err := os.ReadFile(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatalf("ssh_config fragment was not installed: %v", err)
	}
	for _, want := range []string{"Host bastion.example.com", "CertificateFile", "IdentitiesOnly yes"} {
		if !strings.Contains(string(conf), want) {
			t.Errorf("fragment is missing %q:\n%s", want, conf)
		}
	}
}

// Running it twice must not duplicate the Include line or fail.
func TestInstallerScriptIsIdempotent(t *testing.T) {
	t.Parallel()

	script := issueInstaller(t, "bastion", "ssh-bastion")
	home := runInstaller(t, script)
	runInstallerIn(t, script, home)

	conf, err := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		t.Fatalf("read ssh config: %v", err)
	}
	if got := strings.Count(string(conf), "Include ~/.ssh/gruff/*/config"); got != 1 {
		t.Errorf("Include appears %d times after two runs, want 1:\n%s", got, conf)
	}
}

// An existing ~/.ssh/config must be preserved, with the Include placed ahead of
// it so gruff's settings win the first-match-wins lookup.
func TestInstallerScriptPreservesAnExistingConfig(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	existing := "Host myserver\n    User me\n"
	confPath := filepath.Join(home, ".ssh", "config")
	if err := os.WriteFile(confPath, []byte(existing), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	runInstallerIn(t, issueInstaller(t, "bastion", "ssh-bastion"), home)

	conf, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("read ssh config: %v", err)
	}
	got := string(conf)
	if !strings.Contains(got, existing) {
		t.Errorf("existing config was lost:\n%s", got)
	}
	include := strings.Index(got, "Include ~/.ssh/gruff/*/config")
	host := strings.Index(got, "Host myserver")
	if include < 0 || include > host {
		t.Errorf("Include must precede existing Host blocks:\n%s", got)
	}
}

// The script must not reach the network: everything it writes is in the file.
func TestInstallerScriptContactsNothing(t *testing.T) {
	t.Parallel()

	script := issueInstaller(t, "bastion", "ssh-bastion")
	for _, forbidden := range []string{"curl", "wget", "nc ", "/dev/tcp"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("installer references %q; it must be self-contained", forbidden)
		}
	}
}

func TestInstallerScriptIsValidShell(t *testing.T) {
	t.Parallel()

	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh available")
	}

	path := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(path, []byte(issueInstaller(t, "bastion", "ssh-bastion")), 0o700); err != nil {
		t.Fatalf("write script: %v", err)
	}

	out, err := exec.Command(sh, "-n", path).CombinedOutput()
	if err != nil {
		t.Errorf("script is not valid POSIX shell: %v\n%s", err, out)
	}
}

// issueInstaller performs a real issuance through the handler and returns the
// script body.
func issueInstaller(t *testing.T, profile, role string) string {
	t.Helper()

	w := request(t, newTestPortal(t), "POST", "/ssh/"+profile+"/issue", "alice", role)
	if w.Code != 200 {
		t.Fatalf("issue: status %d, body %s", w.Code, w.Body)
	}
	return w.Body.String()
}

func runInstaller(t *testing.T, script string) string {
	t.Helper()

	home := t.TempDir()
	runInstallerIn(t, script, home)
	return home
}

func runInstallerIn(t *testing.T, script, home string) {
	t.Helper()

	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh available")
	}

	path := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("write script: %v", err)
	}

	cmd := exec.Command(sh, path)
	cmd.Env = append(os.Environ(), "HOME="+home)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("installer failed: %v\n%s", err, out)
	}
}
