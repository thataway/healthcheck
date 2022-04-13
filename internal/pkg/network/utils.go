package network

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/multierr"
)

//SockUtils ...
var SockUtils sockUtils

type (
	sockUtils        struct{}
	sockAddrStringer struct {
		syscall.Sockaddr
	}
	//TCPAddrInfo ...
	TCPAddrInfo struct {
		Network string
		Domain  int
		IP      net.IP
		port    int
	}
	//ConnWrapper ...
	ConnWrapper struct {
		net.Conn
	}
)

const (
	TCP  = "tcp"  //nolint
	TCP4 = "tcp4" //nolint
	TCP6 = "tcp6" //nolint
)

const (
	IP  = "ip"  //nolint
	IP4 = "ip4" //nolint
	IP6 = "ip6" //nolint
)

const (
	UDP  = "udp"  //nolint
	UDP4 = "udp4" //nolint
	UDP6 = "udp6" //nolint
)

const (
	ICMP   = "icmp"      //nolint
	ICMP1  = "1"         //nolint
	ICMP6  = "ipv6-icmp" //nolint
	ICMP58 = "58"        //nolint
)

//String ...
func (ss sockAddrStringer) String() string {
	switch sa := ss.Sockaddr.(type) {
	case *syscall.SockaddrInet4:
		return net.JoinHostPort(net.IP(sa.Addr[:]).String(), strconv.Itoa(sa.Port))
	case *syscall.SockaddrInet6:
		return net.JoinHostPort(net.IP(sa.Addr[:]).String(), strconv.Itoa(sa.Port))
	case *syscall.SockaddrUnix:
		return sa.Name
	case nil:
		return "<nil>"
	default:
		return fmt.Sprintf("(unsupported - %T)", sa)
	}
}

//SockAddrStringer ...
func (utils sockUtils) SockAddrStringer(s syscall.Sockaddr) fmt.Stringer {
	return sockAddrStringer{Sockaddr: s}
}

//SetSocketMarkFromConn ...
func (utils sockUtils) SetSocketMarkFromConn(conn interface{}, mark int) error { //conn in [net.Conn, net.PacketConn, so on]
	const api = "SetSocketMarkFromConn"

	type face interface {
		SyscallConn() (syscall.RawConn, error)
	}
	f, ok := conn.(face)
	if !ok || f == nil {
		return errors.Errorf("%s: no way to do it", api)
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return errors.Wrap(err, api)
	}
	err1 := rc.Control(func(fd uintptr) {
		err = SockUtils.SetSocketMark(int(fd), mark)
	})
	return errors.Wrap(multierr.Combine(err, err1), api)
}

// SocketAddress ...
func (inf TCPAddrInfo) SocketAddress() syscall.Sockaddr {
	var ret syscall.Sockaddr
	switch strings.ToLower(inf.Network) {
	case TCP4:
		sa := &syscall.SockaddrInet4{Port: inf.port}
		copy(sa.Addr[:], inf.IP)
		ret = sa
	case TCP6:
		sa := &syscall.SockaddrInet6{Port: inf.port}
		copy(sa.Addr[:], inf.IP)
		ret = sa
	}
	return ret
}

//GetTcpSocketInfo ...
func (utils sockUtils) GetTcpSocketInfo(ipPortAddress string) (TCPAddrInfo, error) { //nolint:revive
	const api = "GetTcpSocketInfo"

	var ret TCPAddrInfo
	host, port, err := net.SplitHostPort(ipPortAddress)
	if err != nil {
		return ret, errors.Wrap(err, api)
	}

	if ret.IP = net.ParseIP(host); ret.IP == nil {
		return ret, errors.Errorf("%s: provided host[%s] is not IP", api, host)
	}
	if ret.port, err = strconv.Atoi(port); err != nil {
		return ret, fmt.Errorf("invalid provided port[%q]", port)
	}
	if strings.Contains(host, ":") {
		ret.Network = TCP6
		ret.Domain = syscall.AF_INET6
		ret.IP = ret.IP.To16()
		if ret.IP == nil {
			return ret, errors.Errorf("%s: invalid provided host[%s] as is not IPv6", api, host)
		}
	} else {
		ret.Network = TCP4
		ret.Domain = syscall.AF_INET
		ret.IP = ret.IP.To4()
		if ret.IP == nil {
			return ret, errors.Errorf("%s: invalid provided host[%s] as is not IPv4", api, host)
		}
	}
	return ret, nil
}

//SetSocketRdTimeout ...
func (utils sockUtils) SetSocketRdTimeout(fd int, duration time.Duration) error {
	const api = "SetSockRdTimeout"
	tv := syscall.NsecToTimeval(duration.Nanoseconds())
	err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	return errors.Wrap(os.NewSyscallError("SetsockoptTimeval", err), api)
}

//SetSocketWrTimeout ...
func (utils sockUtils) SetSocketWrTimeout(fd int, duration time.Duration) error {
	const api = "SetSocketWrTimeout"
	tv := syscall.NsecToTimeval(duration.Nanoseconds())
	err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv)
	return errors.Wrap(os.NewSyscallError("SetsockoptTimeval", err), api)
}

//ResolveIPAndMakeSocketAddress ...
func (utils sockUtils) ResolveIPAndMakeSocketAddress(family int, address string) (syscall.Sockaddr, error) {
	switch family {
	case syscall.AF_INET:
		a, err := net.ResolveIPAddr(IP4, address)
		if err != nil {
			return nil, errors.Wrapf(err, "resolve IP from address('%s')", address)
		}
		if len(a.IP) == 0 {
			a.IP = net.IPv4zero
		}
		ip := a.IP.To4()
		if ip == nil {
			return nil, net.InvalidAddrError(fmt.Sprintf("non-ipv4('%s') from address('%s')", a.IP, address))
		}
		a.IP = ip
		sa := new(syscall.SockaddrInet4)
		copy(sa.Addr[:], ip)
		return sa, nil
	case syscall.AF_INET6:
		a, err := net.ResolveIPAddr(IP6, address)
		if err != nil {
			return nil, errors.Wrapf(err, "resolve IP from address('%s')", address)
		}
		if len(a.IP) == 0 || a.IP.Equal(net.IPv4zero) {
			a.IP = net.IPv6unspecified
		}
		ip := a.IP.To16()
		if ip == nil || ip.To4() != nil {
			return nil, net.InvalidAddrError(fmt.Sprintf("non-ipv6('%s') from address('%s')", a.IP, address))
		}
		sa := &syscall.SockaddrInet6{ZoneId: utils.IPZoneToIndex(a.Zone)}
		copy(sa.Addr[:], ip)
		return sa, nil
	}
	return nil, net.InvalidAddrError(fmt.Sprintf("unexpected family(%v)", family))
}

//IPZoneToIndex ...
func (utils sockUtils) IPZoneToIndex(zone string) uint32 {
	if len(zone) == 0 {
		return 0
	}
	if ifi, err := net.InterfaceByName(zone); err == nil {
		return uint32(ifi.Index)
	}
	n, err := strconv.Atoi(zone)
	if err != nil {
		return 0
	}
	return uint32(n)
}
