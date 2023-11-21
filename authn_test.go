// Copyright 2023 Buf Technologies, Inc.
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
	"strings"
	"testing"

	"github.com/bufbuild/authn-go"
	"github.com/stretchr/testify/assert"
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
		assert.Nil(t, err)
		for k, vals := range headers {
			for _, v := range vals {
				req.Header.Add(k, v)
			}
		}
		res, err := server.Client().Do(req)
		assert.Nil(t, err)
		assert.Equal(t, res.StatusCode, expectCode)
		assert.Nil(t, res.Body.Close())
	}
	// Middleware should ignore non-RPC requests.
	assertResponse(http.Header{}, 200)
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
	assert.Equal(tb, name, hero)
	if id := authn.GetInfo(authn.WithoutInfo(ctx)); id != nil {
		tb.Fatalf("got info %v after WithoutInfo", id)
	}
}

func authenticate(_ context.Context, req authn.Request) (any, error) {
	parts := strings.SplitN(req.Header().Get("Authorization"), " ", 2)
	if len(parts) < 2 || parts[0] != "Bearer" {
		err := authn.Errorf("expected Bearer authentication scheme")
		err.Meta().Set("WWW-Authenticate", "Bearer")
		return nil, err
	}
	if tok := parts[1]; tok != passphrase {
		return nil, authn.Errorf("%q is not the magic passphrase", tok)
	}
	return hero, nil
}
