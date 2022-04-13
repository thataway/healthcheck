package healthcheck

import (
	"context"
	_ "embed"
	"encoding/json"
	"net/url"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/pkg/errors"
	"github.com/thataway/common-lib/logger"
	"github.com/thataway/common-lib/server"
	srvDef "github.com/thataway/healthcheck/pkg/healthcheck"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

//NewHealthChecker creates healthChecker service
func NewHealthChecker(ctx context.Context) server.APIService {
	return &healthCheckerImpl{
		appCtx: ctx,
	}
}

var (
	_ server.APIService          = (*healthCheckerImpl)(nil)
	_ server.APIGatewayProxy     = (*healthCheckerImpl)(nil)
	_ srvDef.HealthCheckerServer = (*healthCheckerImpl)(nil)
)

//go:embed healthchecker.swagger.json
var rawSwagger []byte

//GetSwaggerDocs get swagger spec docs
func GetSwaggerDocs() (*server.SwaggerSpec, error) {
	const api = "healthcheck/GetSwaggerDocs"
	ret := new(server.SwaggerSpec)
	err := json.Unmarshal(rawSwagger, ret)
	return ret, errors.Wrap(err, api)
}

type healthCheckerImpl struct {
	srvDef.UnimplementedHealthCheckerServer
	appCtx context.Context //nolint:structcheck,unused
}

//RegisterGRPC registers GRPC server
func (srv *healthCheckerImpl) RegisterGRPC(_ context.Context, s *grpc.Server) error {
	srvDef.RegisterHealthCheckerServer(s, srv)
	return nil
}

//RegisterProxyGW registers GRPC-GW Mux
func (srv *healthCheckerImpl) RegisterProxyGW(ctx context.Context, mux *runtime.ServeMux, c *grpc.ClientConn) error {
	const api = "healthcheck/RegisterGateway"
	err := srvDef.RegisterHealthCheckerHandler(ctx, mux, c)
	return errors.Wrap(err, api)
}

func (srv *healthCheckerImpl) correctError(err error) error {
	if err != nil && status.Code(err) == codes.Unknown {
		switch errors.Cause(err) {
		case context.DeadlineExceeded:
			return status.New(codes.DeadlineExceeded, err.Error()).Err()
		case context.Canceled:
			return status.New(codes.Canceled, err.Error()).Err()
		default:
			if e := new(url.Error); errors.As(err, &e) {
				switch errors.Cause(e.Err) {
				case context.Canceled:
					return status.New(codes.Canceled, err.Error()).Err()
				case context.DeadlineExceeded:
					return status.New(codes.DeadlineExceeded, err.Error()).Err()
				default:
					if e.Timeout() {
						return status.New(codes.DeadlineExceeded, err.Error()).Err()
					}
				}
			}
			err = status.New(codes.Internal, err.Error()).Err()
		}
	}
	return err
}

//Description returns grpc.ServiceDesc
func (srv *healthCheckerImpl) Description() grpc.ServiceDesc {
	return srvDef.HealthChecker_ServiceDesc
}

func (srv *healthCheckerImpl) addSpanDbgEvent(ctx context.Context, span trace.Span, eventName string, opts ...trace.EventOption) {
	if logger.IsLevelEnabled(ctx, zap.DebugLevel) {
		span.AddEvent(eventName, opts...)
	}
}
