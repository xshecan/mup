package transport

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/xshecan/mup/protocol"
)

func ParsePortSpec(spec string) (uint16, protocol.TransportID, error) {
	portText, name, ok := strings.Cut(spec, "/")
	if !ok || portText == "" || name == "" || strings.Contains(name, "/") {
		return 0, 0, fmt.Errorf("transport must use PORT/udp or PORT/icmp")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return 0, 0, fmt.Errorf("invalid port %q", portText)
	}
	var id protocol.TransportID
	switch name {
	case "udp":
		id = protocol.TransportUDP
	case "icmp":
		id = protocol.TransportICMP
	default:
		return 0, 0, fmt.Errorf("unsupported transport %q", name)
	}
	return uint16(port), id, nil
}
