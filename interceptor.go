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

package authn

import (
	"context"
	"errors"

	connectv1 "connectrpc.com/connect"
	"connectrpc.com/connect/v2"
)

// An InterceptorAuthFunc authenticates a connect-go v2 RPC from its
// [connect.CallInfo]. The function must return an error if the call cannot be
// authenticated. Use [connect.Errorf] with [connect.CodeUnauthenticated] to
// build it. Connect-go v1 errors, such as from [Errorf], are converted.
//
// If the call is successfully authenticated, the function may return some
// information about the authenticated caller (or nil). If non-nil, the
// information is attached to the context using [SetInfo].
//
// Implementations must be safe to call concurrently.
type InterceptorAuthFunc func(ctx context.Context, info *connect.CallInfo) (any, error)

// NewServerInterceptor returns a connect-go v2 [connect.ServerInterceptor]
// that authenticates every RPC, unary or streaming, before calling the
// handler. If authentication succeeds, the authentication information (if any)
// is attached to the context and may be retrieved with [GetInfo].
//
// Unlike [Middleware], it only runs for RPCs that reach the [connect.Server]:
// unknown procedures and malformed requests are rejected without
// authentication. It only protects the interceptors after it, so pass it
// first to [connect.NewServer].
//
// For connect-go v1, use [NewMiddleware].
func NewServerInterceptor(auth InterceptorAuthFunc) connect.ServerInterceptor {
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			callInfo, ok := connect.CallInfoForServerContext(ctx)
			if !ok {
				return connect.NewError(connect.CodeInternal, "authn: missing server call info")
			}
			authInfo, err := auth(ctx, callInfo)
			if err != nil {
				return asV2Error(err, callInfo)
			}
			return next(SetInfo(ctx, authInfo), spec, stream)
		}
	}
}

// asV2Error converts a connect-go v1 error to v2, adding its metadata to the
// response headers. Like v1 handlers, metadata of wire errors is dropped.
func asV2Error(err error, callInfo *connect.CallInfo) error {
	if _, ok := errors.AsType[*connect.Error](err); ok {
		return err
	}
	v1Err, ok := errors.AsType[*connectv1.Error](err)
	if !ok {
		return err
	}
	v2Err := connect.NewError(connect.Code(v1Err.Code()), v1Err.Message()).WithCause(err)
	for _, detail := range v1Err.Details() {
		v2Err = v2Err.WithDetail(&connect.ErrorDetail{
			Type:  detail.Type(),
			Value: detail.Bytes(),
			Debug: nil,
		})
	}
	if connectv1.IsWireError(v1Err) {
		return v2Err
	}
	for key, values := range v1Err.Meta() {
		for _, value := range values {
			callInfo.ResponseHeader().Add(key, value)
		}
	}
	return v2Err
}
