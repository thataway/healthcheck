package icmp

import (
	"net"
	"strings"
	"syscall"

	"github.com/thataway/healthcheck/internal/pkg/network"
	"github.com/pkg/errors"
)

type utils struct{}

//nolint:nakedret
func (u utils) protoAndFamilyFromNetwork(networkName string) (proto, family int, err error) {
	networkName = strings.TrimSpace(strings.ToLower(networkName))
	networkParts := strings.Split(networkName, ":")
	if n := len(networkParts); n < 1 || n > 2 {
		err = net.UnknownNetworkError(networkName)
		return
	}
	xtractProto := func() int {
		if len(networkParts) > 1 {
			switch networkParts[1] {
			case network.ICMP, network.ICMP1:
				return ProtocolICMP
			case network.ICMP6, network.ICMP58:
				return ProtocolIPv6ICMP
			}
		}
		return 0
	}
	switch networkParts[0] {
	case network.UDP, network.UDP4, network.UDP6:
		if len(networkParts) > 1 {
			err = net.UnknownNetworkError(networkName)
			return
		}
	}
	switch networkParts[0] {
	case network.UDP4:
		family, proto = syscall.AF_INET, ProtocolICMP
	case network.UDP6:
		family, proto = syscall.AF_INET6, ProtocolIPv6ICMP
	case network.IP4:
		if proto = xtractProto(); proto == 0 {
			proto = ProtocolICMP
		} else if proto != ProtocolICMP {
			err = net.UnknownNetworkError(networkName)
		}
	case network.IP6:
		if proto = xtractProto(); proto == 0 {
			proto = ProtocolIPv6ICMP
		} else if proto != ProtocolIPv6ICMP {
			err = net.UnknownNetworkError(networkName)
		}
	case network.IP:
		if proto = xtractProto(); proto == 0 {
			err = net.UnknownNetworkError(networkName)
		}
	}
	return
}

func (u utils) listenByDefault(networkName, address string) (net.PacketConn, error) {
	c, err := net.ListenPacket(networkName, address)
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) && strings.Contains(addrErr.Err, "port") { //TODO: dirty hack
		address1 := net.JoinHostPort(address, "0")
		var err1 error
		if c, err1 = net.ListenPacket(networkName, address1); err1 != nil {
			return nil, err
		}
		err = nil
	}
	return c, err
}
