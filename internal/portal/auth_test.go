package portal

import (
	"slices"
	"testing"
)

func TestMergeRolesUnionAndDedupe(t *testing.T) {
	t.Parallel()
	got := mergeRoles([]string{"a", "b"}, []string{"b", "c"})
	want := []string{"a", "b", "c"}
	if !slices.Equal(got, want) {
		t.Fatalf("mergeRoles() = %v, want %v", got, want)
	}
	if got := mergeRoles(nil, nil); len(got) != 0 {
		t.Fatalf("mergeRoles(nil, nil) = %v, want empty", got)
	}
}

func TestIdentifyMergesLocalRolesInProxyMode(t *testing.T) {
	t.Parallel()
	p, _ := buildTestPortal(t, 0)
	p.cfg.Auth.LocalRoles = map[string][]string{"alice": {"local-vpn"}}

	id := p.identify(newRequest("GET", "/", "alice", "provider-vpn"))
	if !slices.Contains(id.Roles, "local-vpn") {
		t.Fatalf("identify() roles = %v, want local-vpn present", id.Roles)
	}
	if !slices.Contains(id.Roles, "provider-vpn") {
		t.Fatalf("identify() dropped provider role; roles = %v", id.Roles)
	}
	if id.Admin {
		t.Fatal("admin should be false without an admin role")
	}
}

func TestIdentifyLocalRolesCanGrantAdmin(t *testing.T) {
	t.Parallel()
	p, _ := buildTestPortal(t, 0)
	p.cfg.AdminRoles = []string{"gruff-admin"}
	p.cfg.Auth.LocalRoles = map[string][]string{"alice": {"gruff-admin"}}

	id := p.identify(newRequest("GET", "/", "alice", ""))
	if !id.Admin {
		t.Fatalf("identify() local role should grant admin; roles = %v", id.Roles)
	}
}

func TestIdentifyLocalRolesIgnoredForOtherUsers(t *testing.T) {
	t.Parallel()
	p, _ := buildTestPortal(t, 0)
	p.cfg.Auth.LocalRoles = map[string][]string{"alice": {"local-vpn"}}

	id := p.identify(newRequest("GET", "/", "bob", ""))
	if slices.Contains(id.Roles, "local-vpn") {
		t.Fatalf("identify() granted bob a role meant for alice; roles = %v", id.Roles)
	}
}
