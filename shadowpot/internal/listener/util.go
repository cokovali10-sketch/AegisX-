package listener

import (
	"net"
	"strconv"
)

// portOf extracts the listening port from a listener address.
func portOf(addr net.Addr) int {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.Port
	}
	if _, port, err := net.SplitHostPort(addr.String()); err == nil {
		if n, perr := strconv.Atoi(port); perr == nil {
			return n
		}
	}
	return 0
}
