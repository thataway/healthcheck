package healthcheck

import (
	"context"
	"net"
	"testing"

	srvDef "github.com/thataway/healthcheck/pkg/healthcheck"
	"github.com/stretchr/testify/assert"
)

func Test_TcpCheckTRUE(t *testing.T) {
	lis, err := net.Listen("tcp", "localhost:5003")
	assert.NoError(t, err, "listen localhost:5003")
	if err != nil {
		return
	}
	defer lis.Close() //nolint
	addr := lis.Addr().String()
	ctx := context.Background()
	srv := &healthCheckerImpl{appCtx: ctx}
	req := &srvDef.TcpCheckRequest{
		AddressToCheck: addr,
	}
	var resp *srvDef.HealthCheckResponse
	resp, err = srv.TcpCheck(ctx, req)
	assert.NoErrorf(t, err, "TCP check '%s", addr)
	if err != nil {
		return
	}
	assert.Equalf(t, true, resp.GetIsOk(), "unexpected result on TCP check '%s", addr)
}

func Test_TcpCheckFALSE(t *testing.T) {
	addr := "127.0.0.1:5004"
	ctx := context.Background()
	srv := &healthCheckerImpl{appCtx: ctx}
	req := &srvDef.TcpCheckRequest{
		AddressToCheck: addr,
	}
	var resp *srvDef.HealthCheckResponse
	var err error
	resp, err = srv.TcpCheck(ctx, req)
	assert.NoErrorf(t, err, "TCP check '%s", addr)
	if err != nil {
		return
	}
	assert.Equalf(t, false, resp.GetIsOk(), "unexpected result on TCP check '%s", addr)
}
