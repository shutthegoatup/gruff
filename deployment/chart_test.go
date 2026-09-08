// Package deployment tests the configuration the Helm chart ships.
//
// The chart is the one part of Gruff that nothing else exercises: it is YAML
// inside YAML, so a key the portal no longer understands, a profile with a bad
// CIDR, or a path that no longer lines up with what the portal writes all
// render perfectly and fail at rollout. Three defects have reached it that way.
package deployment

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	"github.com/shutthegoatup/gruff/internal/config"
)

const chartValues = "helm/gruff/values.yaml"

// chartFiles returns the files the chart drops into its ConfigMap, keyed by
// name: values.yaml holds them as one opaque string so Helm need not know
// anything about their contents.
func chartFiles(t *testing.T) map[string]string {
	t.Helper()

	raw, err := os.ReadFile(chartValues)
	if err != nil {
		t.Fatalf("read %s: %v", chartValues, err)
	}

	var values struct {
		Config string `yaml:"config"`
	}
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatalf("parse %s: %v", chartValues, err)
	}

	files := map[string]string{}
	if err := yaml.Unmarshal([]byte(values.Config), &files); err != nil {
		t.Fatalf("parse the config block in %s: %v", chartValues, err)
	}
	return files
}

func TestChartConfigLoads(t *testing.T) {
	files := chartFiles(t)
	body, ok := files["gruff.yml"]
	if !ok {
		t.Fatalf("the chart ships no gruff.yml, only %v", keys(files))
	}

	dir := t.TempDir()

	// The only substitution: the session key is a Secret in the cluster, so
	// its path cannot exist here. Everything else is loaded as it ships.
	keyPath := filepath.Join(dir, "session.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatalf("write session key: %v", err)
	}
	body = strings.Replace(body, "/etc/gruff/auth/session.key", keyPath, 1)
	t.Setenv("GRUFF_CLIENT_SECRET", "test-secret")

	path := filepath.Join(dir, "gruff.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("the config the chart ships does not load: %v", err)
	}

	// The chart exposes the portal through an Ingress. In proxy mode Gruff
	// authenticates nobody and believes the X-Auth-* headers of whatever
	// reaches the port, so shipping that default here would hand anyone who
	// can resolve the hostname whichever roles they cared to name.
	if cfg.Auth.Mode != config.AuthOIDC {
		t.Errorf("chart auth mode is %q; an internet-facing portal must authenticate its own callers", cfg.Auth.Mode)
	}
}

// The certificate's common name is the user, not the profile, so routes are
// pushed by a hook the portal writes rather than by client-config-dir. That
// only works while both halves agree on where the files are, and they are
// configured in two different files.
func TestChartOpenVPNReadsWhatThePortalWrites(t *testing.T) {
	files := chartFiles(t)

	body, ok := files["gruff.yml"]
	if !ok {
		t.Fatal("the chart ships no gruff.yml")
	}
	var portal struct {
		ConfigdirEnabled bool   `yaml:"configdir-enabled"`
		ConfigdirPath    string `yaml:"configdir-path"`
	}
	if err := yaml.Unmarshal([]byte(body), &portal); err != nil {
		t.Fatalf("parse gruff.yml: %v", err)
	}
	if !portal.ConfigdirEnabled {
		t.Fatal("configdir is disabled, so the portal publishes neither routes nor a CRL")
	}

	conf, ok := files["openvpn.conf"]
	if !ok {
		t.Fatal("the chart ships no openvpn.conf")
	}
	for _, want := range []struct{ directive, suffix string }{
		{"client-connect", "rules/connect.sh"},
		{"crl-verify", "crl.pem"},
	} {
		got := directiveArg(conf, want.directive)
		if got == "" {
			t.Errorf("openvpn.conf has no %s directive", want.directive)
			continue
		}
		if expected := filepath.Join(portal.ConfigdirPath, want.suffix); got != expected {
			t.Errorf("openvpn.conf %s reads %s, but the portal writes %s",
				want.directive, got, expected)
		}
	}

	// The portal writes into an emptyDir; if the mount moves, it writes into
	// the read-only root filesystem instead and never starts.
	deploy, err := os.ReadFile(filepath.Join("helm", "gruff", "templates", "deployment.yaml"))
	if err != nil {
		t.Fatalf("read deployment.yaml: %v", err)
	}
	if !strings.Contains(string(deploy), "mountPath: "+portal.ConfigdirPath) {
		t.Errorf("nothing is mounted at %s, so the portal has nowhere to publish to", portal.ConfigdirPath)
	}
}

func directiveArg(conf, directive string) string {
	for line := range strings.SplitSeq(conf, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == directive {
			return fields[1]
		}
	}
	return ""
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
