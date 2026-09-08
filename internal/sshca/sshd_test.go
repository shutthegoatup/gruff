package sshca

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The pieces of the SSH path are each covered - the certificate verifies, the
// KRL reads back through ssh-keygen -Q, the installer puts files on disk - but
// nothing had asked the question those add up to: does a Gruff certificate log
// in to a host configured the way /setup says to configure it, and does
// revoking it actually stop that?
//
// These run a real sshd with the directives from the setup page, and connect to
// it with a real ssh.
func TestCertificateLogsInAndRevocationStopsIt(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an sshd")
	}
	h := newSSHDHarness(t)

	creds, err := h.ca.Issue("alice", "bastion", []string{h.login}, time.Hour, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	h.install(t, creds)

	if err := h.connect(); err != nil {
		t.Fatalf("a freshly issued certificate could not log in: %v\n%s", err, h.tail())
	}

	// Revoke it by rewriting the list in place, exactly as the portal
	// publishes it. sshd reads RevokedKeys per authentication, so no restart.
	h.revoke(t, creds.Serial)

	if err := h.connect(); err == nil {
		t.Errorf("the certificate still logs in after being revoked:\n%s", h.tail())
	}
	// And refused for the right reason: a login failing for some unrelated
	// reason would satisfy the check above while revocation did nothing.
	if log := h.tail(); !strings.Contains(log, "revoked") {
		t.Errorf("sshd does not report the certificate as revoked:\n%s", log)
	}
}

// The certificate says which logins it is good for and the host says which it
// will accept; a login needs both. That is what makes a profile's principals a
// grant rather than a suggestion, and it rests on the AuthorizedPrincipalsFile
// line the setup page hands out.
func TestCertificateIsRefusedForAnUnlistedPrincipal(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an sshd")
	}
	h := newSSHDHarness(t)

	// Valid, unexpired, signed by the CA this host trusts - but good for a
	// login the host does not grant.
	creds, err := h.ca.Issue("alice", "bastion", []string{"someone-else"}, time.Hour, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	h.install(t, creds)

	if err := h.connect(); err == nil {
		t.Errorf("logged in with a certificate that does not name this login:\n%s", h.tail())
	}
}

// sshdHarness is a running sshd trusting a fresh Gruff CA, configured the way
// the setup page tells an operator to configure one.
type sshdHarness struct {
	ca      *CA
	login   string
	dir     string
	keyPath string
	krlPath string
	logPath string
	port    int
	ssh     string
}

func newSSHDHarness(t *testing.T) *sshdHarness {
	t.Helper()

	sshd, ssh, keygen := sshBinaries(t)

	// An unprivileged sshd can only complete a login for the user that started
	// it, so that is the principal a certificate has to carry to get in.
	me, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}

	dir := t.TempDir()
	h := &sshdHarness{
		ca:      generateCA(t),
		login:   me.Username,
		dir:     dir,
		keyPath: filepath.Join(dir, "id_ed25519"),
		krlPath: filepath.Join(dir, "gruff_krl"),
		logPath: filepath.Join(dir, "sshd.log"),
		port:    freeTCPPort(t),
		ssh:     ssh,
	}

	caPub := filepath.Join(dir, "gruff_ca.pub")
	writeMode(t, caPub, h.ca.PublicKey()+"\n", 0o644)

	principals := filepath.Join(dir, "auth_principals")
	if err := os.MkdirAll(principals, 0o755); err != nil {
		t.Fatalf("create principals dir: %v", err)
	}
	writeMode(t, filepath.Join(principals, h.login), h.login+"\n", 0o644)

	hostKey := filepath.Join(dir, "ssh_host_ed25519_key")
	if out, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-f", hostKey).CombinedOutput(); err != nil {
		t.Fatalf("generate host key: %v\n%s", err, out)
	}

	h.revoke(t) // an empty list, which sshd requires to exist

	// AuthorizedKeysFile is /dev/null so nothing but the certificate can let
	// anyone in: a passing test cannot be an ambient key belonging to whoever
	// is running it.
	conf := filepath.Join(dir, "sshd_config")
	writeMode(t, conf, fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
TrustedUserCAKeys %s
AuthorizedPrincipalsFile %s/%%u
RevokedKeys %s
AuthorizedKeysFile /dev/null
PasswordAuthentication no
AuthenticationMethods publickey
StrictModes no
PidFile %s/sshd.pid
LogLevel VERBOSE
`, h.port, hostKey, caPub, principals, h.krlPath, dir), 0o644)

	h.start(t, sshd, conf)
	return h
}

// install lays the credential out the way the installer script does.
func (h *sshdHarness) install(t *testing.T, creds Credentials) {
	t.Helper()

	writeMode(t, h.keyPath, creds.PrivateKey, 0o600)
	writeMode(t, h.keyPath+"-cert.pub", creds.Certificate+"\n", 0o644)
}

func (h *sshdHarness) revoke(t *testing.T, serials ...uint64) {
	t.Helper()

	krl, err := h.ca.KRL(serials, time.Now())
	if err != nil {
		t.Fatalf("KRL: %v", err)
	}
	writeMode(t, h.krlPath, string(krl), 0o644)
}

func (h *sshdHarness) connect() error {
	out, err := exec.Command(h.ssh,
		"-p", fmt.Sprint(h.port),
		"-i", h.keyPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		h.login+"@127.0.0.1", "true",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (h *sshdHarness) start(t *testing.T, sshd, conf string) {
	t.Helper()

	if out, err := exec.Command(sshd, "-f", conf, "-E", h.logPath).CombinedOutput(); err != nil {
		t.Fatalf("start sshd: %v\n%s", err, out)
	}

	pidFile := filepath.Join(h.dir, "sshd.pid")
	t.Cleanup(func() {
		body, err := os.ReadFile(pidFile)
		if err != nil {
			return
		}
		var pid int
		if _, err := fmt.Sscan(strings.TrimSpace(string(body)), &pid); err != nil {
			return
		}
		if p, err := os.FindProcess(pid); err == nil {
			_ = p.Kill()
		}
	})

	// It daemonises, so the pid file is what says it is up.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(pidFile); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("sshd never wrote its pid file:\n%s", h.tail())
}

func (h *sshdHarness) tail() string {
	body, err := os.ReadFile(h.logPath)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(lines) > 15 {
		lines = lines[len(lines)-15:]
	}
	return strings.Join(lines, "\n")
}

func sshBinaries(t *testing.T) (sshd, ssh, keygen string) {
	t.Helper()

	// sshd usually lives in sbin, which is not always on a user's PATH.
	for _, candidate := range []string{"sshd", "/usr/sbin/sshd", "/usr/local/sbin/sshd"} {
		if path, err := exec.LookPath(candidate); err == nil {
			sshd = path
			break
		}
	}
	if sshd == "" {
		t.Skip("sshd not available")
	}

	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("ssh not available")
	}
	return sshd, ssh, sshKeygen(t)
}

// freeTCPPort asks the kernel for a port nothing else is using, so a parallel
// run does not collide.
func freeTCPPort(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func writeMode(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()

	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
