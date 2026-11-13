// Copyright 2023-2026 Buf Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authn_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/authn"
	pingv1 "connectrpc.com/authn/internal/gen/authn/ping/v1"
	"connectrpc.com/authn/internal/gen/authn/ping/v1/pingv1connect"
	connectv1 "connectrpc.com/connect"
	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestServerInterceptor(t *testing.T) {
	t.Parallel()
	const procedure = "/ping.v1.PingService/Ping"
	server := connect.NewServer(authn.NewServerInterceptor(authenticateCall))
	server.Register(connect.Method{
		Spec: connect.Spec{
			StreamType:       connect.StreamTypeUnary,
			IdempotencyLevel: connect.IdempotencyUnknown,
			Schema:           nil,
			Procedure:        procedure,
		},
		Handler: func(ctx context.Context, _ connect.Spec, _ connect.ServerStream) error {
			assertInfo(ctx, t)
			return nil
		},
	})
	call := func(authorization string) error {
		info := new(connect.CallInfo)
		if authorization != "" {
			info.RequestHeader().Set("Authorization", authorization)
		}
		return server.Call(t.Context(), procedure, info, nil)
	}
	// Calls without a bearer token should be rejected.
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(call("")))
	// Calls with the right token should be allowed, with auth info attached.
	assert.NoError(t, call("Bearer "+passphrase))
}

func TestServerInterceptorHTTP(t *testing.T) {
	t.Parallel()
	const unknownProcedure = "/authn.ping.v1.PingService/Unknown"
	var unknownCalls atomic.Int32
	authenticate := func(ctx context.Context, info *connect.CallInfo) (any, error) {
		if info.Spec.Procedure == unknownProcedure {
			unknownCalls.Add(1)
		}
		switch info.RequestHeader().Get("V1-Error") {
		case "local":
			err := authn.Errorf("v1 error")
			err.Meta().Set("WWW-Authenticate", "Bearer")
			detail, detailErr := connectv1.NewErrorDetail(wrapperspb.String("detail"))
			require.NoError(t, detailErr)
			err.AddDetail(detail)
			return nil, err
		case "wire":
			err := connectv1.NewWireError(connectv1.CodeUnauthenticated, errors.New("wire error"))
			err.Meta().Set("Upstream", "1")
			return nil, err
		}
		return authenticateCall(ctx, info)
	}
	server := connect.NewServer(authn.NewServerInterceptor(authenticate))
	pingv1connect.RegisterPingServiceHandler(server, &pingHandler{
		UnimplementedPingServiceHandler: pingv1connect.UnimplementedPingServiceHandler{},
	})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	// Bidi streaming needs HTTP/2.
	httpServer := httptest.NewUnstartedServer(mux)
	httpServer.EnableHTTP2 = true
	httpServer.StartTLS()
	t.Cleanup(httpServer.Close)

	post := func(t *testing.T, procedure string, header http.Header) (int, http.Header, string) {
		t.Helper()
		// Invalid JSON: auth must fail before the body is read.
		req, err := http.NewRequestWithContext(
			t.Context(),
			http.MethodPost,
			httpServer.URL+procedure,
			strings.NewReader("not json"),
		)
		require.NoError(t, err)
		req.Header = header
		req.Header.Set("Content-Type", "application/json")
		res, err := httpServer.Client().Do(req)
		require.NoError(t, err)
		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		return res.StatusCode, res.Header, string(body)
	}
	t.Run("unauthenticated", func(t *testing.T) {
		t.Parallel()
		status, _, _ := post(t, pingv1connect.PingServicePingProcedure, http.Header{})
		assert.Equal(t, http.StatusUnauthorized, status)
	})
	t.Run("v1_error", func(t *testing.T) {
		t.Parallel()
		status, header, body := post(t, pingv1connect.PingServicePingProcedure, http.Header{
			"V1-Error": []string{"local"},
		})
		assert.Equal(t, http.StatusUnauthorized, status)
		assert.Equal(t, "Bearer", header.Get("WWW-Authenticate"))
		assert.Contains(t, body, "v1 error")
		assert.Contains(t, body, `"type":"google.protobuf.StringValue"`)
	})
	t.Run("v1_wire_error", func(t *testing.T) {
		t.Parallel()
		status, header, body := post(t, pingv1connect.PingServicePingProcedure, http.Header{
			"V1-Error": []string{"wire"},
		})
		assert.Equal(t, http.StatusUnauthorized, status)
		assert.Empty(t, header.Get("Upstream"))
		assert.Contains(t, body, "wire error")
	})
	t.Run("unknown_procedure", func(t *testing.T) {
		t.Parallel()
		status, _, body := post(t, unknownProcedure, http.Header{})
		assert.Equal(t, http.StatusNotImplemented, status)
		assert.Contains(t, body, `"code":"unimplemented"`)
		assert.Zero(t, unknownCalls.Load())
	})
	protocols := map[string][]connecthttp.Option{
		"connect":  nil,
		"grpc":     {connecthttp.WithGRPC()},
		"grpc_web": {connecthttp.WithGRPCWeb()},
	}
	for name, opts := range protocols {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := pingv1connect.NewPingServiceClient(connect.NewClient(
				connecthttp.NewTransport(httpServer.Client(), httpServer.URL, opts...),
			))
			authCtx, callInfo := connect.NewClientContext(t.Context())
			callInfo.RequestHeader().Set("Authorization", "Bearer "+passphrase)

			_, err := client.Ping(t.Context(), &pingv1.PingRequest{Text: "hello"})
			assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
			_, err = client.Ping(authCtx, &pingv1.PingRequest{Text: "hello"})
			require.NoError(t, err)

			stream, err := client.PingStream(t.Context())
			require.NoError(t, err)
			assert.NoError(t, stream.CloseSend())
			_, err = stream.Receive()
			assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
			require.NoError(t, stream.Close())

			authCtx, callInfo = connect.NewClientContext(t.Context())
			callInfo.RequestHeader().Set("Authorization", "Bearer "+passphrase)
			stream, err = client.PingStream(authCtx)
			require.NoError(t, err)
			require.NoError(t, stream.Send(&pingv1.PingStreamRequest{Text: "hello"}))
			res, err := stream.Receive()
			require.NoError(t, err)
			assert.Equal(t, "hello", res.GetText())
			assert.NoError(t, stream.CloseSend())
			assert.NoError(t, stream.Close())
		})
	}
}

func authenticateCall(_ context.Context, info *connect.CallInfo) (any, error) {
	token, ok := authn.BearerTokenFromHeader(info.RequestHeader())
	if !ok {
		return nil, connect.Errorf(connect.CodeUnauthenticated, "expected Bearer authentication scheme")
	}
	if token != passphrase {
		return nil, connect.Errorf(connect.CodeUnauthenticated, "%q is not the magic passphrase", token)
	}
	return hero, nil
}
