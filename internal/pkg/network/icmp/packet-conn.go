package icmp

import (
	"net"
	"runtime"
	"sync"
	"syscall"

	"github.com/pkg/errors"
	"golang.org/x/net/ipv4"
)

var _ net.PacketConn = (*packetConnWrapped)(nil)

type packetConnWrapped struct {
	net.PacketConn
	wrapper      interface{}
	closeOnce    sync.Once
	errFromClose error
}

func (c *packetConnWrapped) Close() error {
	c.closeOnce.Do(func() {
		c.errFromClose = c.PacketConn.Close()
	})
	return c.errFromClose
}

func (c *packetConnWrapped) SyscallConn() (syscall.RawConn, error) {
	type face interface {
		SyscallConn() (syscall.RawConn, error)
	}
	f, ok := c.PacketConn.(face)
	if !ok {
		return nil, errors.New("unsupported 'SyscallConn'")
	}
	return f.SyscallConn()
}

// ReadFrom reads an ICMP message from the connection.
func (c *packetConnWrapped) ReadFrom(b []byte) (int, net.Addr, error) {
	// Please be informed that ipv4.NewPacketConn enables
	// IP_STRIPHDR option by default on Darwin.
	// See golang.org/issue/9395 for further information.
	if runtime.GOOS == "darwin" {
		p, _ := c.wrapper.(*ipv4.PacketConn)
		if p != nil {
			n, _, peer, err := p.ReadFrom(b)
			return n, peer, err //nolint:wrapcheck
		}
	}
	return c.PacketConn.ReadFrom(b) //nolint:wrapcheck
}
