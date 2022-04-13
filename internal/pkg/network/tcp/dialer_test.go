package tcp

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/thataway/healthcheck/internal/pkg/network"
	"github.com/stretchr/testify/assert"
)

func Test_DialerOK(t *testing.T) {
	lis, err := net.Listen("tcp", "localhost:5002")
	assert.NoErrorf(t, err, "tcp listen")
	if err != nil {
		return
	}
	defer lis.Close() //nolint
	ctx := context.Background()
	addr := lis.Addr().String()
	nw := lis.Addr().Network()
	d := NewDialer()
	var conn net.Conn
	conn, err = d.DialContext(ctx, nw, addr)
	assert.NoErrorf(t, err, "DialContext on %s://%s", nw, addr)
	if err != nil {
		return
	}
	_ = conn.Close()
}

func Test_DialerFAIL(t *testing.T) {
	ctx := context.Background()
	addr := "127.0.0.1:5012"
	d := NewDialer()
	var conn net.Conn
	var err error
	conn, err = d.DialContext(ctx, network.TCP, addr)
	assert.Errorf(t, err, "DialContext on '%s'", addr)
	if err == nil {
		_ = conn.Close()
		return
	}
	var e ErrUnableConnect
	assert.Equal(t, true, errors.As(err, &e))
}
