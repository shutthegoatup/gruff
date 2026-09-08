// Package config loads and validates the operator-supplied configuration.
//
// Validation is strict and happens at startup: anything that could produce an
// unsafe certificate or a malformed rule fails the process, not a request.
package config

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"text/template"
	"time"

	"go.yaml.in/yaml/v3"
)

// MaxSessionDuration caps how long an issued client certificate may remain
// valid, regardless of what a profile asks for.
const MaxSessionDuration = 24 * time.Hour

// defaultIssuesPerHour is generous for a person and still bounds a client
// stuck in a loop.
const defaultIssuesPerHour = 20

const (
	defaultListen         = "127.0.0.1:9000"
	defaultFullnameHeader = "X-Auth-Fullname"
	defaultUsernameHeader = "X-Auth-Username"
	defaultRolesHeader    = "X-Auth-Roles"
	defaultBanner         = "VPN Portal"
)

// profileName is deliberately narrow: a profile name reaches both a generated
// file path and the certificate subject.
var profileName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

var (
	validProtocols = []string{"tcp", "udp", "icmp"}
	validActions   = []string{"ACCEPT", "DROP", "REJECT"}
)

// ErrNoProfile is returned by [Config.Profile] for an unknown profile name.
var ErrNoProfile = errors.New("profile not found")

// Duration adapts [time.Duration] to YAML, which has no native duration scalar.
type Duration time.Duration

// UnmarshalYAML decodes a Go duration string such as "2h".
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) String() string { return time.Duration(d).String() }

// Human renders the duration for display: "2 hours", "30 minutes", "1h 30m".
func (d Duration) Human() string {
	td := time.Duration(d)
	h, m := int(td.Hours()), int(td.Minutes())%60

	switch {
	case h == 0:
		return plural(m, "minute")
	case m == 0:
		return plural(h, "hour")
	default:
		return fmt.Sprintf("%dh %dm", h, m)
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// Network is an IPv4 CIDR. Routes and rule destinations are both written this
// way; OpenVPN's dotted-quad form is derived, never configured.
type Network netip.Prefix

// ParseNetwork parses an IPv4 CIDR, rejecting anything that would be ambiguous
// once expanded into a route or a firewall rule.
func ParseNetwork(s string) (Network, error) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return Network{}, fmt.Errorf("parse network %q: %w", s, err)
	}
	if !prefix.Addr().Is4() {
		return Network{}, fmt.Errorf("network %s: must be IPv4", s)
	}
	if prefix.Addr() != prefix.Masked().Addr() {
		return Network{}, fmt.Errorf("network %s: host bits are set, did you mean %s?", s, prefix.Masked())
	}
	return Network(prefix), nil
}

// UnmarshalYAML accepts a CIDR such as "192.168.1.0/24".
func (n *Network) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	parsed, err := ParseNetwork(s)
	if err != nil {
		return err
	}
	*n = parsed
	return nil
}

// String renders the canonical CIDR form.
func (n Network) String() string { return netip.Prefix(n).String() }

// Addr is the network address, e.g. "192.168.1.0".
func (n Network) Addr() string { return netip.Prefix(n).Addr().String() }

// Netmask is the dotted-quad mask OpenVPN's "push route" directive requires,
// e.g. "255.255.255.0".
func (n Network) Netmask() string {
	mask := net.CIDRMask(netip.Prefix(n).Bits(), 32)
	return net.IP(mask).String()
}

// Rule is a firewall rule opened on the VPN server for the life of a session.
type Rule struct {
	Destination Network `yaml:"dest"`
	Port        int     `yaml:"port,omitempty"`
	Protocol    string  `yaml:"protocol,omitempty"`
	Action      string  `yaml:"action"`
}

// Profile is a named set of routes and rules a user may hold a certificate for.
type Profile struct {
	Name        string    `yaml:"name"`
	Description string    `yaml:"description"`
	Duration    Duration  `yaml:"max-session"`
	Roles       []string  `yaml:"roles"`
	Routes      []Network `yaml:"routes"`
	Rules       []Rule    `yaml:"rules"`
}

// AllowedFor reports whether any of the caller's roles grants this profile.
// Access is denied by default: a profile granting no roles matches nobody.
func (p Profile) AllowedFor(roles []string) bool {
	return slices.ContainsFunc(p.Roles, func(required string) bool {
		return slices.Contains(roles, required)
	})
}

// validExtensions are the OpenSSH certificate extensions a profile may grant.
// Anything outside this set is a configuration error rather than something
// quietly passed to sshd.
var validExtensions = []string{
	"permit-X11-forwarding",
	"permit-agent-forwarding",
	"permit-port-forwarding",
	"permit-pty",
	"permit-user-rc",
}

// defaultExtensions is what a profile grants when it says nothing: an
// interactive shell and nothing else. Forwarding is opt-in.
var defaultExtensions = []string{"permit-pty", "permit-user-rc"}

// principalName matches a POSIX-portable login name.
var principalName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// SSHProfile is a named grant of SSH access: which logins a certificate is
// valid for, for how long, and who may ask for one.
type SSHProfile struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Duration    Duration `yaml:"max-session"`
	Roles       []string `yaml:"roles"`
	Principals  []string `yaml:"principals"`
	Extensions  []string `yaml:"extensions"`
	Hosts       []string `yaml:"hosts"`
}

// AllowedFor reports whether any of the caller's roles grants this profile.
// Access is denied by default, exactly as for VPN profiles.
func (p SSHProfile) AllowedFor(roles []string) bool {
	return slices.ContainsFunc(p.Roles, func(required string) bool {
		return slices.Contains(roles, required)
	})
}

// GrantedExtensions is the extension set to stamp into a certificate.
func (p SSHProfile) GrantedExtensions() []string {
	if len(p.Extensions) == 0 {
		return defaultExtensions
	}
	return p.Extensions
}

func (p SSHProfile) validate() error {
	if !profileName.MatchString(p.Name) {
		return fmt.Errorf("name must match %s", profileName)
	}
	if len(p.Roles) == 0 {
		return errors.New("no roles: a profile granting no roles is unreachable")
	}
	if len(p.Principals) == 0 {
		return errors.New("no principals: a certificate valid for no login is useless")
	}
	for _, principal := range p.Principals {
		if !principalName.MatchString(principal) {
			return fmt.Errorf("principal %q must match %s", principal, principalName)
		}
	}
	for _, ext := range p.Extensions {
		if !slices.Contains(validExtensions, ext) {
			return fmt.Errorf("extension %q must be one of %s", ext, strings.Join(validExtensions, ", "))
		}
	}
	d := time.Duration(p.Duration)
	if d <= 0 {
		return errors.New("max-session must be greater than zero")
	}
	if d > MaxSessionDuration {
		return fmt.Errorf("max-session %s exceeds the %s ceiling", d, MaxSessionDuration)
	}
	return nil
}

// Config is the fully validated portal configuration.
type Config struct {
	Listen string `yaml:"listen"`
	// MetricsListen serves Prometheus metrics on its own address. Unset means
	// no metrics: the series name profiles and usage, which does not belong on
	// the same listener as the portal itself.
	MetricsListen string `yaml:"metrics-listen"`

	Auth Auth `yaml:"auth"`

	FullnameHeader string `yaml:"fullname-header"`
	UsernameHeader string `yaml:"username-header"`
	RolesHeader    string `yaml:"roles-header"`

	// AdminRoles may view and revoke every session, not only their own. Empty
	// means nobody can: there is no implicit administrator.
	AdminRoles []string `yaml:"admin-roles"`

	CACertificateFile string `yaml:"ca-certificate-file"`
	CAPrivateFile     string `yaml:"ca-private-file"`

	SSHCAPrivateFile string `yaml:"ssh-ca-private-file"`

	// IssuesPerHour caps issuance per user. Zero disables the limit.
	IssuesPerHour *int `yaml:"issues-per-hour"`

	ConfigdirEnabled bool   `yaml:"configdir-enabled"`
	ConfigdirPath    string `yaml:"configdir-path"`

	Profiles    []Profile    `yaml:"profiles"`
	SSHProfiles []SSHProfile `yaml:"ssh-profiles"`
	Template    string       `yaml:"template"`

	Banner    string `yaml:"banner"`
	LogoutURL string `yaml:"logout-url"`
	HelpURL   string `yaml:"help-url"`

	profileTemplate *template.Template
}

// Load reads, decodes and validates the configuration at path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &c, nil
}

// Profile looks up a profile by name.
func (c *Config) Profile(name string) (Profile, error) {
	i := slices.IndexFunc(c.Profiles, func(p Profile) bool { return p.Name == name })
	if i < 0 {
		return Profile{}, fmt.Errorf("%q: %w", name, ErrNoProfile)
	}
	return c.Profiles[i], nil
}

// IsAdmin reports whether any of the caller's roles grants administration.
// With no admin-roles configured this is always false.
func (c *Config) IsAdmin(roles []string) bool {
	return slices.ContainsFunc(c.AdminRoles, func(required string) bool {
		return slices.Contains(roles, required)
	})
}

// IssueLimit is the per-user hourly cap; zero means unlimited.
func (c *Config) IssueLimit() int {
	if c.IssuesPerHour == nil {
		return defaultIssuesPerHour
	}
	return *c.IssuesPerHour
}

// SSHProfile looks up an SSH profile by name.
func (c *Config) SSHProfile(name string) (SSHProfile, error) {
	i := slices.IndexFunc(c.SSHProfiles, func(p SSHProfile) bool { return p.Name == name })
	if i < 0 {
		return SSHProfile{}, fmt.Errorf("%q: %w", name, ErrNoProfile)
	}
	return c.SSHProfiles[i], nil
}

// ProfileTemplate is the operator-supplied .ovpn template, parsed at load time.
func (c *Config) ProfileTemplate() *template.Template { return c.profileTemplate }

// Roles splits a proxy-supplied roles header into individual role names.
func Roles(header string) []string {
	var roles []string
	for r := range strings.SplitSeq(header, ",") {
		if r = strings.TrimSpace(r); r != "" {
			roles = append(roles, r)
		}
	}
	return roles
}

func (c *Config) validate() error {
	c.Listen = cmp.Or(c.Listen, defaultListen)
	c.FullnameHeader = cmp.Or(c.FullnameHeader, defaultFullnameHeader)
	c.UsernameHeader = cmp.Or(c.UsernameHeader, defaultUsernameHeader)
	c.RolesHeader = cmp.Or(c.RolesHeader, defaultRolesHeader)
	c.Banner = cmp.Or(c.Banner, defaultBanner)

	if err := c.Auth.validate(); err != nil {
		return fmt.Errorf("auth: %w", err)
	}

	if len(c.Profiles) == 0 && len(c.SSHProfiles) == 0 {
		return errors.New("no profiles configured")
	}
	if (c.CACertificateFile == "") != (c.CAPrivateFile == "") {
		return errors.New("ca-certificate-file and ca-private-file must be set together")
	}
	if c.IssuesPerHour != nil && *c.IssuesPerHour < 0 {
		return fmt.Errorf("issues-per-hour %d cannot be negative; use 0 to disable", *c.IssuesPerHour)
	}
	if c.ConfigdirEnabled && c.ConfigdirPath == "" {
		return errors.New("configdir-enabled requires configdir-path")
	}

	// A link the portal renders must be a real absolute URL. Logout in
	// particular is only shown when configured, because in trusted-header mode
	// Gruff holds no session of its own and cannot end one: the URL has to
	// point at whatever does (the proxy's sign-out endpoint). A control that
	// cannot work should not be on the page at all.
	for _, link := range []struct{ name, value string }{
		{"logout-url", c.LogoutURL},
		{"help-url", c.HelpURL},
	} {
		if link.value == "" {
			continue
		}
		u, err := url.Parse(link.value)
		if err != nil {
			return fmt.Errorf("%s: %w", link.name, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("%s %q must be an absolute http or https URL", link.name, link.value)
		}
		if u.Host == "" {
			return fmt.Errorf("%s %q has no host", link.name, link.value)
		}
	}
	// The .ovpn template is only needed if VPN profiles are configured; an
	// SSH-only deployment has nothing to render with it.
	if len(c.Profiles) > 0 {
		if c.Template == "" {
			return errors.New("template is empty")
		}
		tmpl, err := template.New("profile").Parse(c.Template)
		if err != nil {
			return fmt.Errorf("parse template: %w", err)
		}
		c.profileTemplate = tmpl
	}

	seen := make(map[string]bool, len(c.Profiles))
	for i, p := range c.Profiles {
		if err := p.validate(); err != nil {
			return fmt.Errorf("profile %d (%q): %w", i, p.Name, err)
		}
		if seen[p.Name] {
			return fmt.Errorf("duplicate profile %q", p.Name)
		}
		seen[p.Name] = true
	}

	sshSeen := make(map[string]bool, len(c.SSHProfiles))
	for i, p := range c.SSHProfiles {
		if err := p.validate(); err != nil {
			return fmt.Errorf("ssh profile %d (%q): %w", i, p.Name, err)
		}
		if sshSeen[p.Name] {
			return fmt.Errorf("duplicate ssh profile %q", p.Name)
		}
		sshSeen[p.Name] = true
	}
	return nil
}

func (p Profile) validate() error {
	if !profileName.MatchString(p.Name) {
		return fmt.Errorf("name must match %s", profileName)
	}
	if len(p.Roles) == 0 {
		return errors.New("no roles: a profile granting no roles is unreachable")
	}
	d := time.Duration(p.Duration)
	if d <= 0 {
		return errors.New("max-session must be greater than zero")
	}
	if d > MaxSessionDuration {
		return fmt.Errorf("max-session %s exceeds the %s ceiling", d, MaxSessionDuration)
	}
	for _, r := range p.Rules {
		if err := r.validate(); err != nil {
			return err
		}
	}
	return nil
}

// Networks are validated as they are decoded, so a rule only needs its
// remaining fields checked here.
func (r Rule) validate() error {
	if !slices.Contains(validActions, r.Action) {
		return fmt.Errorf("action %q must be one of %s", r.Action, strings.Join(validActions, ", "))
	}
	if r.Protocol != "" && !slices.Contains(validProtocols, r.Protocol) {
		return fmt.Errorf("protocol %q must be one of %s", r.Protocol, strings.Join(validProtocols, ", "))
	}
	if r.Port != 0 {
		if r.Protocol != "tcp" && r.Protocol != "udp" {
			return fmt.Errorf("port %d requires protocol tcp or udp", r.Port)
		}
		if r.Port < 1 || r.Port > 65535 {
			return fmt.Errorf("port %d out of range", r.Port)
		}
	}
	return nil
}
