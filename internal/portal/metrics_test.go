package portal

import (
	"net/http"
	"strings"
	"testing"
)

func TestMetricsCountIssuance(t *testing.T) {
	t.Parallel()

	h, m := newTestPortalWithMetrics(t)

	request(t, h, http.MethodPost, "/profile/livedata/issue", "alice", "vpn-livedata")
	request(t, h, http.MethodPost, "/profile/livedata/issue", "alice", "vpn-livedata")
	request(t, h, http.MethodPost, "/ssh/bastion/issue", "alice", "ssh-bastion")

	body := m(t)
	for _, want := range []string{
		`gruff_certificates_issued_total{kind="vpn",profile="livedata"} 2`,
		`gruff_certificates_issued_total{kind="ssh",profile="bastion"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

// Denials are the series worth alerting on.
func TestMetricsCountDenials(t *testing.T) {
	t.Parallel()

	h, m := newTestPortalWithMetrics(t)

	request(t, h, http.MethodPost, "/profile/secret/issue", "mallory", "vpn-livedata")
	request(t, h, http.MethodGet, "/profile/secret", "mallory", "vpn-livedata")
	request(t, h, http.MethodPost, "/ssh/dbadmin/issue", "mallory", "ssh-bastion")

	body := m(t)
	if !strings.Contains(body, `gruff_authorization_denied_total{kind="vpn"} 2`) {
		t.Errorf("VPN denials not counted:\n%s", body)
	}
	if !strings.Contains(body, `gruff_authorization_denied_total{kind="ssh"} 1`) {
		t.Errorf("SSH denials not counted:\n%s", body)
	}
}

func TestMetricsExpositionIsWellFormed(t *testing.T) {
	t.Parallel()

	h, m := newTestPortalWithMetrics(t)
	request(t, h, http.MethodPost, "/profile/livedata/issue", "alice", "vpn-livedata")

	body := m(t)

	// Every series needs its HELP and TYPE, once, before its samples.
	for _, want := range []string{
		"# HELP gruff_certificates_issued_total",
		"# TYPE gruff_certificates_issued_total counter",
		"# TYPE gruff_build_info gauge",
		// Two label sets, one TYPE line: a repeat is a parse error.
		"# TYPE gruff_revocations_active gauge",
		"# HELP gruff_revocations_active",
	} {
		if strings.Count(body, want) != 1 {
			t.Errorf("expected exactly one %q in:\n%s", want, body)
		}
	}
	if !strings.HasSuffix(body, "\n") {
		t.Error("exposition must end with a newline")
	}
}

// A username reaches a label, and usernames are not constrained the way
// profile names are.
func TestMetricsEscapesLabelValues(t *testing.T) {
	t.Parallel()

	got := formatLabels([]string{"user", `a"b\c` + "\n" + "d"})
	want := `{user="a\"b\\c\nd"}`
	if got != want {
		t.Errorf("formatLabels = %s, want %s", got, want)
	}
}

func TestMetricsRateLimitCounter(t *testing.T) {
	t.Parallel()

	h, m := newTestPortalWithMetricsAndLimit(t, 1)

	request(t, h, http.MethodPost, "/profile/livedata/issue", "alice", "vpn-livedata")
	request(t, h, http.MethodPost, "/profile/livedata/issue", "alice", "vpn-livedata")

	if body := m(t); !strings.Contains(body, "gruff_rate_limited_total 1") {
		t.Errorf("rate limit not counted:\n%s", body)
	}
}
