package openvpn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shutthegoatup/gruff/internal/config"
)

var testProfile = config.Profile{
	Name:   "livedata",
	Routes: mustNetworks("192.168.1.0/24", "10.0.0.0/8"),
	Rules: []config.Rule{
		{Destination: mustNetwork("192.168.1.0/24"), Port: 53, Protocol: "tcp", Action: "ACCEPT"},
		{Destination: mustNetwork("10.0.0.0/8"), Protocol: "icmp", Action: "ACCEPT"},
		{Destination: mustNetwork("0.0.0.0/0"), Action: "DROP"},
	},
}

func TestWriteRoutes(t *testing.T) {
	t.Parallel()

	want := "push \"route 192.168.1.0 255.255.255.0\"\n" +
		"push \"route 10.0.0.0 255.0.0.0\"\n"

	var b strings.Builder
	if err := WriteRoutes(&b, testProfile); err != nil {
		t.Fatalf("WriteRoutes(): %v", err)
	}
	if got := b.String(); got != want {
		t.Errorf("WriteRoutes() =\n%q\nwant\n%q", got, want)
	}
}

func TestWriteRules(t *testing.T) {
	t.Parallel()

	var b strings.Builder
	if err := WriteRules(&b, testProfile); err != nil {
		t.Fatalf("WriteRules(): %v", err)
	}
	got := b.String()

	want := []string{
		"set -euo pipefail",
		`if [[ -z "${CHAIN_NAME:-}" ]]; then`,
		`iptables -A "${CHAIN_NAME}" -p tcp --destination 192.168.1.0/24 --dport 53 -j ACCEPT`,
		`iptables -A "${CHAIN_NAME}" -p icmp --destination 10.0.0.0/8 -j ACCEPT`,
		`iptables -A "${CHAIN_NAME}" --destination 0.0.0.0/0 -j DROP`,
	}
	for _, line := range want {
		if !strings.Contains(got, line) {
			t.Errorf("WriteRules() missing %q, got:\n%s", line, got)
		}
	}

	// An unset chain must not be expanded into an unqualified iptables call.
	if strings.Contains(got, "iptables -A ${CHAIN_NAME}") {
		t.Error("CHAIN_NAME is interpolated unquoted")
	}
	if strings.Contains(got, "--dport 0") {
		t.Error("a rule with no port emitted --dport 0")
	}
}

func TestWriteCreatesBothFilesPerProfile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := Write(dir, []config.Profile{testProfile}); err != nil {
		t.Fatalf("Write(): %v", err)
	}

	for _, path := range []string{
		filepath.Join(dir, "livedata"),
		filepath.Join(dir, "rules", "livedata"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", path)
		}
		if perm := info.Mode().Perm(); perm != 0o640 {
			t.Errorf("%s mode = %#o, want 0640", path, perm)
		}
	}
}

// Profile names are validated upstream, but Write anchors the join regardless:
// this is the last line of defence before a config value becomes a file path.
func TestWriteRefusesToEscapeTheDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	escaping := []string{"../escaped", "../../etc/cron.d/evil", "nested/name", "..", "/absolute"}

	for _, name := range escaping {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := Write(t.TempDir(), []config.Profile{{Name: name}})
			if err == nil {
				t.Fatalf("Write(%q) succeeded, want a rejection", name)
			}
			if !strings.Contains(err.Error(), "escapes") {
				t.Errorf("Write(%q) error = %v, want it to mention escaping", name, err)
			}
		})
	}

	if entries, err := os.ReadDir(dir); err == nil && len(entries) != 0 {
		t.Errorf("files were written outside the target directory: %v", entries)
	}
}

func mustNetwork(s string) config.Network {
	n, err := config.ParseNetwork(s)
	if err != nil {
		panic(err)
	}
	return n
}

func mustNetworks(ss ...string) []config.Network {
	out := make([]config.Network, 0, len(ss))
	for _, s := range ss {
		out = append(out, mustNetwork(s))
	}
	return out
}
