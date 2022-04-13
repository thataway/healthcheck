package healthcheck

import (
	"context"
	"net"
	"time"

	"github.com/thataway/healthcheck/internal/pkg/network/tcp"
	srvDef "github.com/thataway/healthcheck/pkg/healthcheck"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

//TcpCheck impl service
func (srv *healthCheckerImpl) TcpCheck(ctx context.Context, req *srvDef.TcpCheckRequest) (resp *srvDef.HealthCheckResponse, err error) { ////nolint:revive
	defer func() {
		err = srv.correctError(err)
	}()

	var tmo time.Duration
	addr := req.GetAddressToCheck()
	mark := req.GetSocketMark()

	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String("addressToCheck", addr),
		attribute.Int64("socketMark", mark),
	)

	if dur := req.GetTimeout(); dur != nil {
		err = dur.CheckValid()
		if err != nil {
			err = status.Errorf(codes.InvalidArgument,
				"invalid 'timeout' is provided: %v", err)
			return
		}
		tmo = dur.AsDuration()
		span.SetAttributes(
			attribute.Stringer("timeout", tmo),
		)
	}
	d := tcp.NewDialer(tcp.OptSocketMark{SocketMark: int(mark)},
		tcp.OptSocketConnectTimeout{Timeout: tmo})
	var conn net.Conn
	conn, err = d.DialContext(ctx, "tcp", addr)
	resp = new(srvDef.HealthCheckResponse)
	if err == nil {
		_ = conn.Close()
		resp.IsOk = true
	} else {
		var exp tcp.ErrUnableConnect
		if errors.As(err, &exp) {
			err = nil
		}
	}
	return //nolint:nakedret
}
