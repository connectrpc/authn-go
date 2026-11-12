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
	"testing"

	"connectrpc.com/authn"
	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
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
