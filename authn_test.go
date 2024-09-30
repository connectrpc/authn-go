// Copyright 2023-2024 Buf Technologies, Inc.
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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/authn"
	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	hero       = "Ali Baba"
	passphrase = "opensesame"
)

func TestMiddleware(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Check-Info") != "" {
			assertInfo(r.Context(), t)
		}
		_, _ = io.WriteString(w, "ok")
	})
	handler := authn.NewMiddleware(authenticate).Wrap(mux)
	server := httptest.NewServer(handler)

	assertResponse := func(headers http.Header, expectCode int) {
		req, err := http.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			server.URL+"/empty.v1/GetEmpty",
			strings.NewReader("{}"),
		)
		require.NoError(t, err)
		for k, vals := range headers {
			for _, v := range vals {
				req.Header.Add(k, v)
			}
		}
		res, err := server.Client().Do(req)
		require.NoError(t, err)
		assert.Equal(t, expectCode, res.StatusCode)
		assert.NoError(t, res.Body.Close())
	}
	// Middleware should authenticate non-RPC requests.
	assertResponse(http.Header{}, http.StatusUnauthorized)
	// RPCs without the right bearer token should be rejected.
	assertResponse(
		http.Header{"Content-Type": []string{"application/json"}},
		http.StatusUnauthorized,
	)
	// RPCs with the right token should be allowed.
	assertResponse(
		http.Header{
			"Content-Type":  []string{"application/json"},
			"Authorization": []string{"Bearer " + passphrase},
			"Check-Info":    []string{"1"}, // verify that auth info is attached to context
		},
		http.StatusOK,
	)
}

func assertInfo(ctx context.Context, tb testing.TB) {
	tb.Helper()
	info := authn.GetInfo(ctx)
	if info == nil {
		tb.Fatal("no authentication info")
	}
	name, ok := info.(string)
	assert.True(tb, ok, "got info of type %T, expected string", info)
	assert.Equal(tb, hero, name)
	if id := authn.GetInfo(authn.WithoutInfo(ctx)); id != nil {
		tb.Fatalf("got info %v after WithoutInfo", id)
	}
}

func authenticate(_ context.Context, req *http.Request) (any, error) {
	token, ok := authn.BearerToken(req)
	if !ok {
		err := authn.Errorf("expected Bearer authentication scheme")
		err.Meta().Set("WWW-Authenticate", "Bearer")
		return nil, err
	}
	if token != passphrase {
		return nil, authn.Errorf("%q is not the magic passphrase", token)
	}
	return hero, nil
}

func TestInferProcedures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		url   string
		want  string
		valid bool
	}{
		{name: "simple", url: "http://localhost:8080/foo", want: "/foo", valid: false},
		{name: "service", url: "http://localhost:8080/service/bar", want: "/service/bar", valid: true},
		{name: "trailing", url: "http://localhost:8080/service/bar/", want: "/service/bar/", valid: false},
		{name: "subroute", url: "http://localhost:8080/api/service/bar", want: "/service/bar", valid: true},
		{name: "subrouteTrailing", url: "http://localhost:8080/api/service/bar/", want: "/api/service/bar/", valid: false},
		{name: "missingService", url: "http://localhost:8080//foo", want: "//foo", valid: false},
		{name: "missingMethod", url: "http://localhost:8080/foo//", want: "/foo//", valid: false},
		{
			name:  "real",
			url:   "http://localhost:8080/connect.ping.v1.PingService/Ping",
			want:  "/connect.ping.v1.PingService/Ping",
			valid: true,
		},
	}
	for _, testcase := range tests {
		testcase := testcase
		t.Run(testcase.name, func(t *testing.T) {
			t.Parallel()
			url, err := url.Parse(testcase.url)
			require.NoError(t, err)
			got, valid := authn.InferProcedure(url)
			assert.Equal(t, testcase.want, got)
			assert.Equal(t, testcase.valid, valid)
		})
	}
}

func TestInferProtocol(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		contentType string
		method      string
		params      url.Values
		want        string
		valid       bool
	}{{
		name:        "connectUnary",
		contentType: "application/json",
		method:      http.MethodPost,
		params:      nil,
		want:        connect.ProtocolConnect,
		valid:       true,
	}, {
		name:        "connectStreaming",
		contentType: "application/connec+json",
		method:      http.MethodPost,
		params:      nil,
		want:        connect.ProtocolConnect,
		valid:       true,
	}, {
		name:        "grpcWeb",
		contentType: "application/grpc-web",
		method:      http.MethodPost,
		params:      nil,
		want:        connect.ProtocolGRPCWeb,
		valid:       true,
	}, {
		name:        "grpc",
		contentType: "application/grpc",
		method:      http.MethodPost,
		params:      nil,
		want:        connect.ProtocolGRPC,
		valid:       true,
	}, {
		name:        "connectGet",
		contentType: "",
		method:      http.MethodGet,
		params:      url.Values{"message": []string{"{}"}, "encoding": []string{"json"}},
		want:        connect.ProtocolConnect,
		valid:       true,
	}, {
		name:        "connectGetProto",
		contentType: "",
		method:      http.MethodGet,
		params:      url.Values{"message": []string{""}, "encoding": []string{"proto"}},
		want:        connect.ProtocolConnect,
		valid:       true,
	}, {
		name:        "connectGetMissingParams",
		contentType: "",
		method:      http.MethodGet,
		params:      nil,
		want:        "",
		valid:       false,
	}, {
		name:        "connectGetMissingParam-Message",
		contentType: "",
		method:      http.MethodGet,
		params:      url.Values{"encoding": []string{"json"}},
		want:        "",
		valid:       false,
	}, {
		name:        "connectGetMissingParam-Encoding",
		contentType: "",
		method:      http.MethodGet,
		params:      url.Values{"message": []string{"{}"}},
		want:        "",
		valid:       false,
	}, {
		name:        "connectPutContentType",
		contentType: "application/connect+json",
		method:      http.MethodPut,
		params:      nil,
		want:        "",
		valid:       false,
	}, {
		name:        "nakedGet",
		contentType: "",
		method:      http.MethodGet,
		params:      nil,
		want:        "",
		valid:       false,
	}, {
		name:        "unknown",
		contentType: "text/html",
		method:      http.MethodPost,
		params:      nil,
		want:        "",
		valid:       false,
	}}
	for _, testcase := range tests {
		testcase := testcase
		t.Run(testcase.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(testcase.method, "http://localhost:8080/service/Method", nil)
			if testcase.contentType != "" {
				req.Header.Set("Content-Type", testcase.contentType)
			}
			if testcase.params != nil {
				req.URL.RawQuery = testcase.params.Encode()
			}
			req.Method = testcase.method
			got, valid := authn.InferProtocol(req)
			assert.Equal(t, testcase.want, got, "protocol")
			assert.Equal(t, testcase.valid, valid, "valid")
		})
	}
}
