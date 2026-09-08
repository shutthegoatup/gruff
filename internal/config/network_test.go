package config

import (
	"strings"
	"testing"
)

// A network with host bits set is ambiguous once expanded into a route or an
// iptables rule, so it is rejected rather than silently masked.
func TestNetworkRejectsHostBits(t *testing.T) {
	t.Parallel()

	_, err := ParseNetwork("192.168.1.5/24")
	if err == nil {
		t.Fatal("ParseNetwork accepted a network with host bits set")
	}
	if !strings.Contains(err.Error(), "192.168.1.0/24") {
		t.Errorf("error should suggest the masked form, got: %v", err)
	}
}

func TestNetworkRejects(t *testing.T) {
	t.Parallel()

	for _, s := range []string{
		"not-an-ip",
		"192.168.1.0",          // no prefix length
		"192.168.1.0/33",       // out of range
		"2001:db8::/32",        // IPv6
		"192.168.1.0/24 extra", // trailing junk
		"",
	} {
		if _, err := ParseNetwork(s); err == nil {
			t.Errorf("ParseNetwork(%q) succeeded, want an error", s)
		}
	}
}

// Routes and rule destinations share one representation; the dotted-quad form
// OpenVPN needs is derived, never configured separately.
func TestNetworkNetmask(t *testing.T) {
	t.Parallel()

	tests := map[string]struct{ addr, netmask string }{
		"192.168.1.0/24": {"192.168.1.0", "255.255.255.0"},
		"10.0.0.0/8":     {"10.0.0.0", "255.0.0.0"},
		"172.16.0.0/16":  {"172.16.0.0", "255.255.0.0"},
		"0.0.0.0/0":      {"0.0.0.0", "0.0.0.0"},
		"10.1.2.3/32":    {"10.1.2.3", "255.255.255.255"},
	}

	for cidr, want := range tests {
		n, err := ParseNetwork(cidr)
		if err != nil {
			t.Fatalf("ParseNetwork(%q): %v", cidr, err)
		}
		if got := n.String(); got != cidr {
			t.Errorf("String() = %s, want %s", got, cidr)
		}
		if got := n.Addr(); got != want.addr {
			t.Errorf("%s Addr() = %s, want %s", cidr, got, want.addr)
		}
		if got := n.Netmask(); got != want.netmask {
			t.Errorf("%s Netmask() = %s, want %s", cidr, got, want.netmask)
		}
	}
}
