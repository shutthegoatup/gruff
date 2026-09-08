// Package openvpn writes the per-profile files the OpenVPN server consumes:
// client-config-dir route pushes, and the firewall script run on client connect.
package openvpn

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/shutthegoatup/gruff/internal/config"
)

const (
	fileMode os.FileMode = 0o640
	dirMode  os.FileMode = 0o750
)

// Write emits the ccd and rules files for every profile under dir.
//
// Profile names are validated by the config package before reaching here; the
// join below is nonetheless anchored so that a name can never escape dir.
func Write(dir string, profiles []config.Profile) error {
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, dirMode); err != nil {
		return fmt.Errorf("create %s: %w", rulesDir, err)
	}

	for _, p := range profiles {
		ccdPath, err := safeJoin(dir, p.Name)
		if err != nil {
			return err
		}
		rulesPath, err := safeJoin(rulesDir, p.Name)
		if err != nil {
			return err
		}
		if err := writeFile(ccdPath, func(w io.Writer) error { return WriteRoutes(w, p) }); err != nil {
			return err
		}
		if err := writeFile(rulesPath, func(w io.Writer) error { return WriteRules(w, p) }); err != nil {
			return err
		}
	}
	return nil
}

// WriteRoutes emits the client-config-dir entry pushing a profile's routes.
//
// Routes are configured as CIDR; OpenVPN's push directive wants a dotted-quad
// netmask, so the conversion happens here rather than in the configuration.
func WriteRoutes(w io.Writer, p config.Profile) error {
	for _, n := range p.Routes {
		if _, err := fmt.Fprintf(w, "push \"route %s %s\"\n", n.Addr(), n.Netmask()); err != nil {
			return err
		}
	}
	return nil
}

// WriteRules emits the iptables script appending a profile's rules to $CHAIN_NAME.
//
// Every interpolated value has been validated as an enum, a CIDR or a numeric
// port, so none of them can carry shell or iptables metacharacters.
func WriteRules(w io.Writer, p config.Profile) error {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\n")
	b.WriteString("set -euo pipefail\n\n")
	b.WriteString("if [[ -z \"${CHAIN_NAME:-}\" ]]; then\n")
	b.WriteString("\techo \"CHAIN_NAME is not set\" >&2\n")
	b.WriteString("\texit 1\n")
	b.WriteString("fi\n\n")

	for _, r := range p.Rules {
		b.WriteString("iptables -A \"${CHAIN_NAME}\"")
		if r.Protocol != "" {
			fmt.Fprintf(&b, " -p %s", r.Protocol)
		}
		fmt.Fprintf(&b, " --destination %s", r.Destination)
		if r.Port != 0 {
			fmt.Fprintf(&b, " --dport %d", r.Port)
		}
		fmt.Fprintf(&b, " -j %s\n", r.Action)
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func writeFile(path string, render func(io.Writer) error) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	if err := render(f); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", path, err)
	}
	return f.Close()
}

// safeJoin accepts only a single, ordinary path element, so that a profile name
// can neither traverse out of dir nor be silently rewritten into it.
func safeJoin(dir, name string) (string, error) {
	if name == "" || name == "." || name == ".." ||
		strings.ContainsRune(name, '/') || strings.ContainsRune(name, filepath.Separator) {
		return "", fmt.Errorf("profile %q escapes %s: not a single path element", name, dir)
	}
	return filepath.Join(dir, name), nil
}
