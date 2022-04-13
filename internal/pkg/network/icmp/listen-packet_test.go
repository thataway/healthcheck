package icmp

import (
	"testing"

	"github.com/thataway/healthcheck/internal/pkg/network"
	"github.com/stretchr/testify/assert"
)

func Test_ICMP_ListenUDP(t *testing.T) {
	networks := []string{
		network.UDP,
		network.UDP4,
		network.UDP6,
	}
	addr := "localhost"
	for _, nw := range networks {
		conn, err := ListenPacket(nw, addr, 0)
		assert.NoErrorf(t, err, "on network '%s': %v", nw, err)
		if err != nil {
			return
		}
		_ = conn.Close()
	}
}
