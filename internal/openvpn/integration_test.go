package openvpn_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shutthegoatup/gruff/internal/config"
	"github.com/shutthegoatup/gruff/internal/openvpn"
	"github.com/shutthegoatup/gruff/internal/pki"
)

// This is the test that was missing. The certificate's common name is the user,
// so client-config-dir cannot select a profile; that mismatch meant routes were
// never pushed and ccd-exclusive refused every client, and nothing caught it
// because the VPN path had only ever been exercised a piece at a time.
//
// It runs a real server and a real client. dev null keeps it out of needing
// root: the control channel, the client-connect hook and the push all happen,
// which is where the breakage was.
func TestOpenVPNPushesProfileRoutes(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an OpenVPN server")
	}
	bin, err := exec.LookPath("openvpn")
	if err != nil {
		t.Skip("openvpn not available")
	}

	dir := t.TempDir()
	profile := config.Profile{Name: "livedata", Routes: mustNets(t, "192.168.44.0/24")}
	if err := openvpn.Write(dir, []config.Profile{profile}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	ca, err := pki.Generate("Gruff Test")
	if err != nil {
		t.Fatalf("Generate CA: %v", err)
	}
	caPath := filepath.Join(dir, "ca.pem")
	write(t, caPath, ca.CertificatePEM())

	// The client credential, exactly as the portal hands it out.
	client, err := ca.Issue("alice", profile.Name, time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	crl, err := ca.CRL(nil, time.Now())
	if err != nil {
		t.Fatalf("CRL: %v", err)
	}
	crlPath := filepath.Join(dir, "crl.pem")
	write(t, crlPath, crl)

	// The server needs its own certificate from the same CA; the portal only
	// issues client ones, so this is signed here.
	server, err := ca.IssueServer("gruff-vpn-server", []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	serverCertPath, serverKeyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	write(t, serverCertPath, []byte(server.Certificate))
	write(t, serverKeyPath, []byte(server.PrivateKey))

	port := freeUDPPort(t)
	serverConf := filepath.Join(dir, "server.conf")
	write(t, serverConf, []byte(fmt.Sprintf(`port %d
proto udp
dev null
ca %s
cert %s
key %s
dh none
server 10.44.0.0 255.255.255.0
topology subnet
script-security 2
client-connect %s
crl-verify %s
keepalive 5 20
verb 4
`, port, caPath, serverCertPath, serverKeyPath, filepath.Join(dir, "rules", "connect.sh"), crlPath)))

	clientConf := filepath.Join(dir, "client.ovpn")
	write(t, clientConf, []byte(fmt.Sprintf(`client
dev null
proto udp
remote 127.0.0.1 %d
remote-cert-tls server
nobind
verb 4
<ca>
%s</ca>
<cert>
%s</cert>
<key>
%s</key>
`, port, ca.CertificatePEM(), client.Certificate, client.PrivateKey)))

	serverLog := run(t, bin, serverConf)
	waitFor(t, serverLog, "UDPv4 link local", 15*time.Second, "server did not start")

	clientLog := run(t, bin, clientConf)
	waitFor(t, clientLog, "Initialization Sequence Completed", 25*time.Second,
		"client never completed the handshake")

	body, err := os.ReadFile(clientLog)
	if err != nil {
		t.Fatalf("read client log: %v", err)
	}
	// The whole point: the hook selected this profile's routes and the server
	// pushed them.
	if !strings.Contains(string(body), "route 192.168.44.0 255.255.255.0") {
		t.Errorf("the profile's route was never pushed:\n%s", tail(string(body), 20))
	}
}

func run(t *testing.T, bin, conf string) string {
	t.Helper()

	logPath := conf + ".log"
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}

	cmd := exec.Command(bin, "--config", conf)
	cmd.Dir = filepath.Dir(conf)
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		t.Fatalf("start openvpn: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		f.Close()
	})
	return logPath
}

func waitFor(t *testing.T, path, want string, limit time.Duration, msg string) {
	t.Helper()

	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if body, err := os.ReadFile(path); err == nil && strings.Contains(string(body), want) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	body, _ := os.ReadFile(path)
	t.Fatalf("%s (waiting for %q):\n%s", msg, want, tail(string(body), 20))
}

func write(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustNets(t *testing.T, cidrs ...string) []config.Network {
	t.Helper()
	out := make([]config.Network, 0, len(cidrs))
	for _, c := range cidrs {
		n, err := config.ParseNetwork(c)
		if err != nil {
			t.Fatalf("ParseNetwork(%q): %v", c, err)
		}
		out = append(out, n)
	}
	return out
}

func tail(s string, lines int) string {
	parts := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	return strings.Join(parts, "\n")
}
