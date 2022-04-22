package healthcheck

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/thataway/healthcheck/internal/pkg/network"
	"github.com/thataway/healthcheck/internal/pkg/network/icmp"
	srvDef "github.com/thataway/protos/pkg/api/healthcheck"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	netIcmp "golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

//IcmpCheck impl service
func (srv *healthCheckerImpl) IcmpCheck(ctx context.Context, req *srvDef.IcmpCheckRequest) (resp *srvDef.HealthCheckResponse, err error) {
	defer func() {
		err = srv.correctError(err)
	}()

	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.String("host", req.GetHost()))

	ass := icmpCheckAssist{req: req}
	var tmo time.Duration
	if tmo, err = ass.getRequestTmo(); err != nil {
		err = status.Errorf(codes.InvalidArgument, "invalid 'timeout' is provided: %s", err)
		return
	}
	ctx1 := ctx
	if tmo > 0 {
		span.SetAttributes(attribute.Stringer("timeout", tmo))
		var cancel func()
		ctx1, cancel = context.WithTimeout(ctx, tmo)
		defer cancel()
	}

	resp = new(srvDef.HealthCheckResponse)
	srv.addSpanDbgEvent(ctx, span, "processEchoExchange")
	err = ass.processEchoExchange(ctx1)
	if err == nil || errors.As(err, new(*net.OpError)) {
		resp.IsOk = err == nil
		err = nil
		return
	}
	if e := new(*net.DNSError); errors.As(err, e) {
		err = status.Errorf(codes.NotFound, "on host('%s') -> dns-err: %s",
			req.GetHost(), (*e).Error())
	}
	return //nolint:nakedret
}

// ------------------------------------------------- A S S I S T A N T S are Below -------------------------------------

var (
	nextEchoSequenceData int32 = -1
)

type icmpCheckAssist struct {
	req *srvDef.IcmpCheckRequest
}

type echoCheckKey string

type icmpEchoExchanger struct {
	pc             net.PacketConn
	echoRequest    []byte
	echoRequestKey echoCheckKey
	icmpProto      int
	addr2ping      net.Addr
}

func (ass icmpCheckAssist) nextEchoSequence() int {
	return int(atomic.AddInt32(&nextEchoSequenceData, 1)) % 65536
}

func (ass icmpCheckAssist) getRequestTmo() (time.Duration, error) {
	const api = "get-request-timeout"

	t := ass.req.GetTimeout()
	if t == nil {
		return 0, nil
	}
	if err := t.CheckValid(); err != nil {
		return 0, errors.Wrap(err, api)
	}
	return t.AsDuration(), nil
}

func (ass icmpCheckAssist) getTargetAddresses(ctx context.Context, asIPAddresses bool) ([]net.Addr, error) {
	const api = "get-target-addresses"

	var port int
	var ips []net.IP
	var host string
	targetAddr := strings.TrimSpace(ass.req.GetHost())
	if h, p, e := net.SplitHostPort(targetAddr); e != nil {
		host = targetAddr
	} else {
		host = h
		if port, e = strconv.Atoi(p); e != nil {
			return nil, errors.Wrapf(e, "%s: bad port('%s')", api, p)
		}
	}
	if len(host) == 0 {
		ips = []net.IP{net.IPv4zero}
	} else if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		resolvedAddresses, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			return nil, errors.Wrap(err, api)
		}
		ips = make([]net.IP, 0, len(resolvedAddresses))
		for i := range resolvedAddresses {
			if ip := net.ParseIP(resolvedAddresses[i]); ip != nil {
				ips = append(ips, ip)
			}
		}
		isIP4 := func(ip net.IP) int {
			if len(ip.To4()) == net.IPv4len {
				return 0
			}
			return 1
		}
		sort.Slice(ips, func(i, j int) bool {
			l, r := ips[i], ips[j]
			return isIP4(l) < isIP4(r)
		})
	}
	ret := make([]net.Addr, 0, len(ips))
	for _, ip := range ips {
		if asIPAddresses {
			ret = append(ret, &net.IPAddr{IP: ip})
		} else {
			ret = append(ret, &net.UDPAddr{IP: ip, Port: port})
		}
	}
	return ret, nil
}

func (ass icmpCheckAssist) makeEchoRequest(icmpProto int) ([]byte, echoCheckKey, error) {
	const api = "make-echo-request"

	var key echoCheckKey
	var msg netIcmp.Message
	switch icmpProto {
	case icmp.ProtocolICMP:
		msg.Type = ipv4.ICMPTypeEcho
	case icmp.ProtocolIPv6ICMP:
		msg.Type = ipv6.ICMPTypeEchoRequest
	default:
		return nil, key, errors.Errorf("%s: unsupported icmo-proto(%v)", api, icmpProto)
	}
	ech := &netIcmp.Echo{
		ID:  os.Getpid() & 0xFFFF,
		Seq: ass.nextEchoSequence(),
	}

	key = echoCheckKey(fmt.Sprintf("echo-%v-%v-%v", os.Getpid(), ech.Seq, time.Now().UnixNano()))
	ech.Data = append(ech.Data, []byte(key)...)
	msg.Body = ech
	ret, err := msg.Marshal(nil)
	return ret, key, errors.Wrap(err, api)
}

func (ass icmpCheckAssist) provideAttrs(ctx context.Context, consumer func(networkName string, addr net.Addr, icmpProto int) error) error {
	currentUser, _ := user.Current()
	privileged := currentUser.Username == "root"

	addresses, err := ass.getTargetAddresses(ctx, privileged)
	if err != nil {
		return err
	}

	if len(addresses) == 0 {
		return errors.New("no one target address is resolved")
	}

	var ip net.IP
	var networkName string
	var proto int
	oneFirstAddress := addresses[0]
	switch t := oneFirstAddress.(type) {
	case *net.IPAddr:
		ip = t.IP
	case *net.UDPAddr:
		ip = t.IP
	}
	if ip4 := ip.To4(); len(ip4) == net.IPv4len {
		proto = icmp.ProtocolICMP
		if privileged {
			networkName = fmt.Sprintf("%s:%s", network.IP4, network.ICMP)
		} else {
			networkName = network.UDP4
		}
	} else if ip6 := ip.To16(); len(ip6) == net.IPv6len {
		proto = icmp.ProtocolIPv6ICMP
		if privileged {
			networkName = fmt.Sprintf("%s:%s", network.IP6, network.ICMP6)
		} else {
			networkName = network.UDP6
		}
	} else {
		return errors.Errorf("IP '%s' is neither IPv4 nor IPv6", ip)
	}

	return consumer(networkName, oneFirstAddress, proto)
}

func (ass icmpCheckAssist) processEchoExchange(ctx context.Context) error {
	const api = "process-echo-exchange"

	err := ass.provideAttrs(ctx, func(networkName string, addr2ping net.Addr, icmpProto int) error {
		echo, echoKey, e := ass.makeEchoRequest(icmpProto)
		if e != nil {
			return e
		}
		socketMark := ass.req.GetSocketMark()
		var conn net.PacketConn
		if conn, e = icmp.ListenPacket(networkName, "", int(socketMark)); e != nil {
			return e
		}
		defer conn.Close() //nolint
		exchanger := icmpEchoExchanger{
			pc:             conn,
			echoRequest:    echo,
			echoRequestKey: echoKey,
			icmpProto:      icmpProto,
			addr2ping:      addr2ping,
		}
		return exchanger.doExchange(ctx)
	})
	return errors.Wrap(err, api)
}

func (k echoCheckKey) imIn(b netIcmp.MessageBody) bool {
	switch t := b.(type) {
	case *netIcmp.Echo:
		return bytes.Contains(t.Data, []byte(k))
	case *netIcmp.RawBody:
		return bytes.Contains(t.Data, []byte(k))
	}
	return false
}

func (exch *icmpEchoExchanger) extractIP(a net.Addr) net.IP {
	switch t := a.(type) {
	case *net.IPAddr:
		return t.IP
	case *net.UDPAddr:
		return t.IP
	}
	return nil
}

func (exch *icmpEchoExchanger) doExchange(ctx context.Context) error {
	done := make(chan error, 1)
	go func() {
		defer close(done)
		_, e := exch.pc.WriteTo(exch.echoRequest, exch.addr2ping)
		if e != nil {
			done <- e
			return
		}
		repl := make([]byte, 512)
		interestIP := exch.extractIP(exch.addr2ping)
		for {
			var a net.Addr
			var n int
			if n, a, e = exch.pc.ReadFrom(repl); e != nil {
				done <- e
				break
			}
			if n == 0 {
				continue
			}
			incomingIP := exch.extractIP(a)
			incomingIP.Equal(incomingIP)
			if !interestIP.Equal(incomingIP) {
				continue
			}
			var msg *netIcmp.Message
			if msg, e = netIcmp.ParseMessage(exch.icmpProto, repl[:n]); e != nil {
				done <- e
				break
			}
			if exch.echoRequestKey.imIn(msg.Body) {
				break
			}
		}
	}()
	var err error
	select {
	case <-ctx.Done():
		_ = exch.pc.Close()
		return ctx.Err()
	case err = <-done:
		return err
	}
}
