package portal

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
)

// metrics is a small Prometheus exposition, written by hand rather than pulling
// in a client library for six counters.
//
// The interesting series is denials: a rise in gruff_authorization_denied_total
// is someone repeatedly asking for access they do not have.
type metrics struct {
	mu     sync.Mutex
	counts map[series]int64
}

// series is a metric name and its label set, flattened so it can key a map.
type series struct {
	name   string
	labels string
}

func newMetrics() *metrics {
	return &metrics{counts: map[series]int64{}}
}

func (m *metrics) inc(name string, labels ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counts[series{name: name, labels: formatLabels(labels)}]++
}

// gauges are collected at scrape time rather than tracked, since they are
// derived from the store.
type gauge struct {
	name, help, labels string
	value              int64
}

// WriteTo renders the exposition. Counters first, then the collected gauges.
func (m *metrics) writeTo(w io.Writer, gauges []gauge) error {
	m.mu.Lock()
	snapshot := maps.Clone(m.counts)
	m.mu.Unlock()

	names := slices.SortedFunc(maps.Keys(snapshot), func(a, b series) int {
		return cmp.Or(strings.Compare(a.name, b.name), strings.Compare(a.labels, b.labels))
	})

	var lastName string
	for _, s := range names {
		if s.name != lastName {
			fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", s.name, counterHelp[s.name], s.name)
			lastName = s.name
		}
		fmt.Fprintf(w, "%s%s %d\n", s.name, s.labels, snapshot[s])
	}

	// HELP and TYPE go once per metric name, not once per label set: a
	// repeated TYPE line is a parse error, and a gauge may have several.
	lastName = ""
	for _, g := range gauges {
		if g.name != lastName {
			fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", g.name, g.help, g.name)
			lastName = g.name
		}
		fmt.Fprintf(w, "%s%s %d\n", g.name, g.labels, g.value)
	}
	return nil
}

const (
	metricIssued      = "gruff_certificates_issued_total"
	metricDenied      = "gruff_authorization_denied_total"
	metricRateLimited = "gruff_rate_limited_total"
	metricRevoked     = "gruff_revocations_total"
	metricSignIn      = "gruff_sign_in_failures_total"
)

var counterHelp = map[string]string{
	metricIssued:      "Certificates issued, by credential kind and profile.",
	metricDenied:      "Requests refused because the caller lacked the role.",
	metricRateLimited: "Issuance requests refused by the per-user rate limit.",
	metricRevoked:     "Credentials revoked, by kind.",
	metricSignIn:      "Sign-ins that did not complete.",
}

// formatLabels renders alternating key/value pairs as a Prometheus label set.
func formatLabels(kv []string) string {
	if len(kv) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i+1 < len(kv); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		// Not %q: it escapes more than the exposition format defines.
		fmt.Fprintf(&b, `%s="%s"`, kv[i], escapeLabel(kv[i+1]))
	}
	b.WriteByte('}')
	return b.String()
}

// escapeLabel guards the exposition against a value containing a quote or a
// newline.
//
// Every label emitted today is bounded - kind, profile, version - and it must
// stay that way: a username or a serial as a label is a new time series per
// value, which is how a metrics backend gets taken down. This is a guard for
// whatever gets added next, not for anything present.
func escapeLabel(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(v)
}

// MetricsHandler serves the exposition. It is mounted on its own listener, not
// the portal mux: a scraper has no session, and the series would otherwise
// disclose profile names and usage to anyone who can reach the portal.
func (p *Portal) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if err := p.metrics.writeTo(w, p.collectGauges(r.Context())); err != nil {
			p.log.ErrorContext(r.Context(), "write metrics", "error", err)
		}
	})
}

func (p *Portal) collectGauges(ctx context.Context) []gauge {
	gauges := []gauge{{
		name:   "gruff_build_info",
		help:   "Build information; always 1.",
		labels: formatLabels([]string{"version", p.version}),
		value:  1,
	}}

	// A store that reports its bound gets it published, because the bound is
	// what decides whether a live credential is still revocable.
	if counter, ok := p.sessions.(interface {
		Tracked(context.Context) (int, int, error)
	}); ok {
		if held, limit, err := counter.Tracked(ctx); err != nil {
			p.log.ErrorContext(ctx, "collect session gauge", "error", err)
		} else {
			gauges = append(gauges,
				gauge{
					name:  "gruff_sessions_tracked",
					help:  "Issued credentials the audit list is holding.",
					value: int64(held),
				},
				gauge{
					name:  "gruff_sessions_capacity",
					help:  "Most the audit list will hold; past it the oldest-expiring are forgotten and can no longer be revoked.",
					value: int64(limit),
				})
		}
	}

	revoker, ok := p.sessions.(Revoker)
	if !ok {
		return gauges
	}

	for _, kind := range []Kind{KindVPN, KindSSH} {
		entries, err := revoker.Revocations(ctx, kind)
		if err != nil {
			p.log.ErrorContext(ctx, "collect revocation gauge", "kind", kind, "error", err)
			continue
		}
		gauges = append(gauges, gauge{
			name:   "gruff_revocations_active",
			help:   "Revoked credentials that have not yet expired.",
			labels: formatLabels([]string{"kind", string(kind)}),
			value:  int64(len(entries)),
		})
	}
	return gauges
}
