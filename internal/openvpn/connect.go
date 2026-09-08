package openvpn

import (
	"fmt"
	"io"
	"strings"
)

// ConnectScript is the client-connect hook OpenVPN runs per connection.
//
// It exists because the certificate's common name is the user, not the profile.
// client-config-dir looks a file up by common name, so it cannot select a
// profile's routes, and ccd-exclusive would refuse every client. OpenVPN
// exports the whole X509 subject to the hook, so the profile is read from
// X509_0_OU and the matching route file is handed back.
func WriteConnectScript(w io.Writer, profiles []string) error {
	var b strings.Builder

	b.WriteString("#!/bin/sh\n")
	b.WriteString("#\n")
	b.WriteString("# Written by Gruff. OpenVPN runs this per connection and reads the\n")
	b.WriteString("# directives this script writes to $1.\n")
	b.WriteString("#\n")
	b.WriteString("# The profile comes from the certificate's OU, which only Gruff can set;\n")
	b.WriteString("# an unrecognised one exits non-zero, which refuses the connection.\n")
	b.WriteString("\n")
	b.WriteString("set -eu\n\n")
	b.WriteString("CONFIG=\"$1\"\n")
	b.WriteString("DIR=$(dirname \"$0\")/..\n")
	b.WriteString("PROFILE=\"${X509_0_OU:-}\"\n\n")

	b.WriteString("if [ -z \"$PROFILE\" ]; then\n")
	b.WriteString("\techo \"gruff: certificate carries no profile\" >&2\n")
	b.WriteString("\texit 1\n")
	b.WriteString("fi\n\n")

	// The OU is set by Gruff from an already-validated name, but this script
	// turns it into a path, so it is checked again here rather than trusted.
	b.WriteString("case \"$PROFILE\" in\n")
	if len(profiles) == 0 {
		b.WriteString("\t*) echo \"gruff: no profiles configured\" >&2; exit 1 ;;\n")
	} else {
		fmt.Fprintf(&b, "\t%s) ;;\n", strings.Join(profiles, "|"))
		b.WriteString("\t*) echo \"gruff: unknown profile $PROFILE\" >&2; exit 1 ;;\n")
	}
	b.WriteString("esac\n\n")

	b.WriteString("ROUTES=\"$DIR/$PROFILE\"\n")
	b.WriteString("if [ ! -f \"$ROUTES\" ]; then\n")
	b.WriteString("\techo \"gruff: no routes for $PROFILE\" >&2\n")
	b.WriteString("\texit 1\n")
	b.WriteString("fi\n\n")
	b.WriteString("cat \"$ROUTES\" > \"$CONFIG\"\n")

	_, err := io.WriteString(w, b.String())
	return err
}
