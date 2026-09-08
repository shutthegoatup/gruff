package openvpn_test

import (
	"net"
	"testing"
)

// freeUDPPort asks the kernel for a port nothing else is using, so a parallel
// run does not collide.
func freeUDPPort(t *testing.T) int {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free port: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}
