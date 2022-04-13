package healthcheck

import (
	"context"
	"net"
	"testing"
	"time"

	srvDef "github.com/thataway/healthcheck/pkg/healthcheck"
	errors2 "github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

func Test_IcmpCheck_LocalHost_OK(t *testing.T) {
	ips, err := net.LookupIP("localhost")
	assert.NoError(t, err, "get '[]IP' from 'localhost'")
	if err != nil {
		return
	}
	assert.NotEqualf(t, 0, len(ips), "[]IPS is zero len")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	apiServer := &healthCheckerImpl{appCtx: context.Background()}
	req := new(srvDef.IcmpCheckRequest)
	for _, ip := range ips {
		req.Host = ip.String()
		resp, err := apiServer.IcmpCheck(ctx, req)
		assert.NoErrorf(t, err, "IP: %s", ip)
		if err != nil {
			return
		}
		assert.Equalf(t, true, resp.GetIsOk(), "IP:%s expected OK")
	}
}

func Test_IcmpCheck_OnHost_OK(t *testing.T) {
	hosts := []string{
		"amazon.com",
		"google.com",
		"microsoft.com",
		"apple.com",
		"ip.server.gravitl.com",
		"ifconfig.me",
		"ipinfo.io",
	}
	host2IP := make(map[string][]net.IP)
	for i := range hosts {
		h := hosts[i]
		ips, _ := net.LookupIP(h)
		for _, ip := range ips {
			if ip4 := ip.To4(); len(ip4) == net.IPv4len {
				host2IP[h] = append(host2IP[h], ip4)
			}
		}
	}
	assert.NotEqual(t, 0, len(host2IP), "found no any IPv4")
	if len(host2IP) == 0 {
		return
	}

	ctx := context.Background()
	apiServer := &healthCheckerImpl{appCtx: ctx}
	req := new(srvDef.IcmpCheckRequest)
	req.Timeout = durationpb.New(time.Second)

	for h, ips := range host2IP {
		req.Host = h
		resp, err := apiServer.IcmpCheck(ctx, req)
		if status.Code(errors2.Cause(err)) == codes.DeadlineExceeded {
			continue
		}
		if !assert.Equalf(t, true, resp.GetIsOk(), "H:'%s'", h) {
			continue
		}
		succeeded := 0
		for _, ip := range ips {
			req.Host = ip.String()
			resp, err = apiServer.IcmpCheck(ctx, req)
			if status.Code(errors2.Cause(err)) == codes.DeadlineExceeded {
				continue
			}
			if !assert.NoErrorf(t, err, "H:'%s', IP:%s", h, ip) {
				continue
			}
			if !assert.Equalf(t, true, resp.GetIsOk(), "H:'%s', IP:%s", h, ip) {
				continue
			}
			succeeded++
		}
		assert.Truef(t, succeeded > 0, "H:'%s'", h)
	}
}

func Test_IcmpCheck_BadHost(t *testing.T) {
	ctx := context.Background()
	apiServer := &healthCheckerImpl{appCtx: ctx}
	req := new(srvDef.IcmpCheckRequest)
	req.Timeout = durationpb.New(time.Second)
	req.Host = "ka-ka-host"
	_, err := apiServer.IcmpCheck(ctx, req)
	assert.Error(t, err)
	if err == nil {
		return
	}
	assert.Equal(t, codes.NotFound, status.Code(errors2.Cause(err)))
}
