package healthcheck

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	srvDef "github.com/thataway/protos/pkg/api/healthcheck"
)

//go:embed test-data/*.json
var testPayloads embed.FS

func traverseVariants(f func(source string, searchNearestFields bool, expectOk bool) error) {
	type strategyT struct {
		searchNearestFields bool
		expectOk            bool
	}
	type sampleT struct {
		source     string
		strategies []strategyT
	}
	samples := []sampleT{
		{
			source: "payload1.json",
			strategies: []strategyT{{false, true},
				{true, true}},
		},
		{
			source: "payload2.json",
			strategies: []strategyT{{false, true},
				{true, false}},
		},
		{
			source: "payload3.json",
			strategies: []strategyT{{false, true},
				{true, true}},
		},
		{
			source: "payload4.json",
			strategies: []strategyT{{false, false},
				{true, false}},
		},
	}
	for _, sample := range samples {
		for _, s := range sample.strategies {
			if err := f(sample.source, s.searchNearestFields, s.expectOk); err != nil {
				return
			}
		}
	}
}

func Test_checkExpectedPayload(t *testing.T) {
	req := new(srvDef.HttpCheckRequest)
	req.Extension = &srvDef.HttpCheckRequestExtension{
		NearSearchMode: false,
		MandatoryData: map[string]string{
			"key1": "value1",
			"key2": "value2",
			"key3": "value3",
		},
	}
	ass := httpCheckAssist{req: req}
	traverseVariants(func(source string, searchNearestFields bool, expectOk bool) error {
		payload, err := testPayloads.ReadFile("test-data/" + source)
		assert.NoErrorf(t, err, "no test data are loaded from '%s' file", source)
		if err != nil {
			return err //nolint:wrapcheck
		}

		reader := bytes.NewReader(payload)
		req.Extension.NearSearchMode = searchNearestFields
		err = ass.checkExpectedPayload(reader)
		assert.Equalf(t, expectOk, err == nil,
			"src:'%s', searchNearestFields: %v, expect-OK: %v",
			source, searchNearestFields, expectOk)
		return nil
	})
}

func Test_statusCodeIsGood(t *testing.T) {
	req := &srvDef.HttpCheckRequest{
		GoodStatusCodes: new(srvDef.HttpStatusCodes),
	}
	req.GoodStatusCodes.Values = append(req.GoodStatusCodes.Values,
		&srvDef.HttpStatusCodes_Value{Is: &srvDef.HttpStatusCodes_Value_Code{Code: 201}},
		&srvDef.HttpStatusCodes_Value{Is: &srvDef.HttpStatusCodes_Value_Code{Code: 202}},
		&srvDef.HttpStatusCodes_Value{Is: &srvDef.HttpStatusCodes_Value_Code{Code: 210}},
		&srvDef.HttpStatusCodes_Value{Is: &srvDef.HttpStatusCodes_Value_Range{
			Range: &srvDef.HttpStatusCodes_Range{From: 300, To: 310},
		}},
		&srvDef.HttpStatusCodes_Value{Is: &srvDef.HttpStatusCodes_Value_Range{
			Range: &srvDef.HttpStatusCodes_Range{From: 320, To: 399},
		}},
	)

	type sampleT struct {
		Code     int
		ExpectOk bool
	}

	samples := []sampleT{
		{
			Code:     200,
			ExpectOk: false,
		},
		{
			Code:     201,
			ExpectOk: true,
		},
		{
			Code:     202,
			ExpectOk: true,
		},
		{
			Code:     210,
			ExpectOk: true,
		},
		{
			Code:     300,
			ExpectOk: true,
		},
		{
			Code:     301,
			ExpectOk: true,
		},
		{
			Code:     319,
			ExpectOk: false,
		},
		{
			Code:     398,
			ExpectOk: true,
		},
	}
	ass := httpCheckAssist{req: req}
	for i := range samples {
		sample := samples[i]
		res := ass.statusCodeIsGood(sample.Code)
		assert.Equalf(t, sample.ExpectOk, res, "Sample %v, Code: %v", i, sample.Code)
	}
}

func Test_HttpCheck(t *testing.T) {
	listener, err := net.Listen("tcp", "localhost:5001")
	assert.NoErrorf(t, err, "listener")
	if err != nil {
		return
	}
	host := listener.Addr().String()
	srv := http.Server{Handler: http.FileServer(http.FS(testPayloads))}
	go func() {
		err := srv.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			return
		}
		assert.NoError(t, err, "test srv")
	}()
	defer srv.Close() //nolint

	time.Sleep(time.Second)
	ctx := context.Background()
	apiServer := &healthCheckerImpl{appCtx: ctx}
	request := new(srvDef.HttpCheckRequest)
	request.AddressToCheck = host
	request.UseMethod = srvDef.HttpCheckRequest_GET
	request.Extension = &srvDef.HttpCheckRequestExtension{
		NearSearchMode: false,
		MandatoryData: map[string]string{
			"key1": "value1",
			"key2": "value2",
			"key3": "value3",
		},
	}

	traverseVariants(func(source string, searchNearestFields bool, expectOk bool) error {
		request.QueryUri = "test-data/" + source
		request.Extension.NearSearchMode = searchNearestFields
		resp, err := apiServer.HttpCheck(ctx, request)
		assert.NoErrorf(t, err, "Http health check on source '%s'", source)
		if err != nil {
			return err
		}
		assert.Equalf(t, expectOk, resp.GetIsOk(), "unexpected result from source '%s'", source)
		if expectOk != resp.GetIsOk() {
			return errors.New("unexpected result")
		}
		return nil
	})
}
