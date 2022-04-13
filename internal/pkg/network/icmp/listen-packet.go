package icmp

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"

	"github.com/thataway/healthcheck/internal/pkg/network"
	"github.com/pkg/errors"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// From https://godoc.org/golang.org/x/net/internal/iana, can't import internal packages
const (
	ProtocolIP       = 0  //nolint IPv4 encapsulation, pseudo protocol number
	ProtocolICMP     = 1  //nolint
	ProtocolIPv6ICMP = 58 //nolint
)

//ListenPacket ...
func ListenPacket(networkName, address string, mark int) (net.PacketConn, error) {
	//nolint:revive
	const sysIP_STRIPHDR = 0x17 //for now only darwin supports this option
	const api = "ListenPacket"
	const osDarwin = "darwin"
	const osIos = "ios"

	proto, family, err := utils{}.protoAndFamilyFromNetwork(networkName)
	if err != nil {
		return nil, errors.Wrap(err, api)
	}
	var (
		c    net.PacketConn
		sock int
		f    *os.File
	)
	defer func() {
		if sock > 0 {
			_ = syscall.Close(sock)
		}
		if f != nil {
			_ = f.Close()
		}
	}()

	switch family {
	case syscall.AF_INET, syscall.AF_INET6:
		if sock, err = syscall.Socket(family, syscall.SOCK_DGRAM, proto); err != nil {
			return nil, errors.Wrap(os.NewSyscallError("socket", err), api)
		}
		if (runtime.GOOS == osDarwin || runtime.GOOS == osIos) && family == syscall.AF_INET {
			if err = syscall.SetsockoptInt(sock, ProtocolIP, sysIP_STRIPHDR, 1); err != nil {
				return nil, errors.Wrap(os.NewSyscallError("setsockopt", err), api)
			}
		}
		var sa syscall.Sockaddr
		if sa, err = network.SockUtils.ResolveIPAndMakeSocketAddress(family, address); err != nil {
			return nil, errors.Wrap(err, api)
		}
		if err = syscall.Bind(sock, sa); err != nil {
			return nil, errors.Wrap(os.NewSyscallError(fmt.Sprintf("socket bind('%s')", address), err), api)
		}
		f = os.NewFile(uintptr(sock), "dgram-icmp")
		sock = -1
		c, err = net.FilePacketConn(f)
	default:
		c, err = utils{}.listenByDefault(networkName, address)
	}
	if err != nil {
		return nil, errors.Wrap(err, api)
	}
	if mark != 0 {
		err = network.SockUtils.SetSocketMarkFromConn(c, mark)
		if err != nil {
			return nil, errors.Wrap(err, api)
		}
	}
	ret := &packetConnWrapped{PacketConn: c}
	switch proto {
	case ProtocolICMP:
		ret.wrapper = ipv4.NewPacketConn(c)
	case ProtocolIPv6ICMP:
		ret.wrapper = ipv6.NewPacketConn(c)
	}
	runtime.SetFinalizer(ret, func(o *packetConnWrapped) {
		_ = o.Close()
	})
	return ret, nil
}
