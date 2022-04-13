package healthcheck

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/thataway/common-lib/pkg/jsonview"
	"github.com/thataway/healthcheck/internal/pkg/network/tcp"
	srvDef "github.com/thataway/healthcheck/pkg/healthcheck"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

//HttpCheck impl service
func (srv *healthCheckerImpl) HttpCheck(ctx context.Context, req *srvDef.HttpCheckRequest) (resp *srvDef.HealthCheckResponse, err error) { //nolint:revive
	defer func() {
		err = srv.correctError(err)
	}()

	span := trace.SpanFromContext(ctx)

	ass := httpCheckAssist{req: req}
	var tmo time.Duration
	var addr string

	srv.addSpanDbgEvent(ctx, span, "construct-request",
		trace.WithAttributes(attribute.Stringer("request", jsonview.Stringer(req))),
	)
	if addr, err = ass.makeRequestAddress(); err != nil {
		err = status.Errorf(codes.InvalidArgument, "invalid 'AddressToCheck' is provided: %v", err)
		return
	}
	span.SetAttributes(attribute.String("check-address", addr))
	if tmo, err = ass.getRequestTmo(); err != nil {
		err = status.Errorf(codes.InvalidArgument, "invalid 'timeout' is provided: %s", err)
		return
	}
	httpCli := ass.makeHTTPClient(tmo)
	var httpReq *http.Request
	if httpReq, err = ass.makeHTTPRequest(ctx, addr); err != nil {
		return
	}
	span.SetAttributes(
		attribute.Stringer("URL", httpReq.URL),
		attribute.String("Method", httpReq.Method),
	)
	if tmo > 0 {
		span.SetAttributes(attribute.Stringer("timeout", tmo))
		ctx1, c := context.WithTimeout(ctx, tmo)
		defer c()
		httpReq = httpReq.WithContext(ctx1)
	}
	var httpResponse *http.Response
	resp = new(srvDef.HealthCheckResponse)
	srv.addSpanDbgEvent(ctx, span, "process-request")
	if httpResponse, err = httpCli.Do(httpReq); httpResponse != nil {
		err = nil
		if httpResponse.Body != nil {
			defer httpResponse.Body.Close() //nolint
		}
		if ass.statusCodeIsGood(httpResponse.StatusCode) {
			e := ass.checkExpectedPayload(httpResponse.Body)
			resp.IsOk = e == nil
		}
	}
	return //nolint:nakedret
}

type httpCheckAssist struct {
	req *srvDef.HttpCheckRequest
}

func (ass httpCheckAssist) makeHTTPRequest(ctx context.Context, host string) (*http.Request, error) {
	const api = "make-HTTP-request"

	queryURI := strings.Trim(ass.req.GetQueryUri(), `\/`)
	uri := fmt.Sprintf("%s://%s/%s", strings.ToLower(ass.req.GetUseScheme().String()), host, queryURI)
	request, err := http.NewRequestWithContext(ctx, ass.req.GetUseMethod().String(), uri, nil)
	if err != nil {
		return nil, errors.Wrap(err, api)
	}
	if headers := ass.req.GetHeader().GetValues(); headers != nil {
		for h, data := range headers {
			values := data.GetData()
			for i := range values {
				request.Header.Add(h, values[i])
			}
		}
	}
	return request, nil
}

func (ass httpCheckAssist) checkExpectedPayload(responseBody io.Reader) error {
	const api = "check-expected-payload"

	type isDict = map[string]interface{}
	type isSlice = []interface{}
	typeOfDict := reflect.TypeOf((*isDict)(nil)).Elem()
	typeOfSlice := reflect.TypeOf((*isSlice)(nil)).Elem()
	ext := ass.req.GetExtension()
	interest := ext.GetMandatoryData()
	if len(interest) == 0 {
		return nil
	}
	if responseBody == nil {
		return errors.Errorf("%s: no payload is here", api)
	}
	var raw interface{}
	decoder := json.NewDecoder(responseBody)
	decoder.UseNumber()
	err := decoder.Decode(&raw)
	if err != nil {
		return errors.Wrapf(err, "%s: payload is in unexpected format", api)
	}
	rawValue := reflect.ValueOf(raw)
	chk := make(map[string]struct{})

	var source isSlice
	if rawType := rawValue.Type(); rawType.ConvertibleTo(typeOfDict) {
		source = append(source, rawValue.Convert(typeOfDict).Interface().(isDict))
	} else if rawType.ConvertibleTo(typeOfSlice) {
		source = rawValue.Convert(typeOfSlice).Interface().(isSlice)
	} else {
		return errors.Wrapf(err, "%s: payload is in unexpected format", api)
	}
loop:
	for _, src := range source {
		v := reflect.ValueOf(src)
		if !v.IsValid() {
			continue
		}
		if !v.Type().ConvertibleTo(typeOfDict) {
			continue
		}
		srcDict := v.Convert(typeOfDict).Interface().(isDict)
		for k, v := range interest {
			v1, ok := srcDict[k]
			if !ok {
				continue
			}
			if !reflect.ValueOf(v1).IsValid() {
				continue
			}
			if !reflect.TypeOf(v1).Comparable() {
				continue
			}
			if v1 == v {
				chk[k] = struct{}{}
				if len(chk) == len(interest) {
					break loop
				}
			}
		}
		if ext.GetNearSearchMode() {
			break
		}
	}
	if len(chk) != len(interest) {
		return errors.Errorf("%s: payload is not satisfied expectations", api)
	}
	return nil
}

func (ass httpCheckAssist) getRequestTmo() (time.Duration, error) {
	const api = "getRequestTmo"

	t := ass.req.GetTimeout()
	if t == nil {
		return 0, nil
	}
	if err := t.CheckValid(); err != nil {
		return 0, errors.Wrap(err, api)
	}
	return t.AsDuration(), nil
}

func (ass httpCheckAssist) makeHTTPClient(dialTmo time.Duration) *http.Client {
	dialer := tcp.NewDialer(tcp.OptSocketConnectTimeout{Timeout: dialTmo},
		tcp.OptSocketMark{SocketMark: int(ass.req.GetSocketMark())})

	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect not permitted")
		},
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
			},
		},
	}
}

func (ass httpCheckAssist) statusCodeIsGood(statusCode2Check int) bool {
	statusCodes := ass.req.GetGoodStatusCodes().GetValues()
	if len(statusCodes) == 0 {
		return statusCode2Check == 200
	}
	for _, item := range statusCodes {
		switch v := item.GetIs().(type) {
		case *srvDef.HttpStatusCodes_Value_Code:
			if statusCode2Check == int(v.Code) {
				return true
			}
		case *srvDef.HttpStatusCodes_Value_Range:
			from, to := int(v.Range.GetFrom()), int(v.Range.GetTo())
			if from <= statusCode2Check && statusCode2Check <= to {
				return true
			}
		}
	}
	return false
}

func (ass httpCheckAssist) makeRequestAddress() (string, error) {
	const api = "makeRequestAddress"

	address := ass.req.GetAddressToCheck()
	if len(address) == 0 {
		return "", errors.Errorf("%s: 'AddressToCheck' is missing in request", api)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		scheme := ass.req.GetUseScheme().String()
		var p int
		if p, err = net.LookupPort("tcp", scheme); err != nil {
			return "", errors.Wrapf(err, "%s: lookup default port", api)
		}
		host, port = address, strconv.Itoa(p)
	}
	if net.ParseIP(host) == nil {
		var ips []net.IP
		if ips, err = net.LookupIP(host); err != nil {
			return "", errors.Wrapf(err, "%s: lookup IP", api)
		}
		if len(ips) > 0 {
			host = ips[0].String()
		} else {
			host = ""
		}
	}
	return net.JoinHostPort(host, port), nil
}
