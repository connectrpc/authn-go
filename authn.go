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

// Package authn provides authentication middleware for [connect].
package authn

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"connectrpc.com/connect"
)

type key int

const infoKey key = iota

// An AuthFunc authenticates an RPC. The function must return an error if the
// request cannot be authenticated. The error is typically produced with
// [Errorf], but any error will do.
//
// If requests are successfully authenticated, the authentication function may
// return some information about the authenticated caller (or nil). If non-nil,
// the information is automatically attached to the context using [SetInfo].
//
// Implementations must be safe to call concurrently.
type AuthFunc func(ctx context.Context, req *http.Request) (any, error)

// SetInfo attaches authentication information to the context. It's often
// useful in tests.
//
// [AuthFunc] implementations do not need to call SetInfo explicitly. Any
// returned authentication information is automatically added to the context by
// [Middleware].
func SetInfo(ctx context.Context, info any) context.Context {
	if info == nil {
		return ctx
	}
	return context.WithValue(ctx, infoKey, info)
}

// GetInfo retrieves authentication information, if any, from the request
// context.
func GetInfo(ctx context.Context) any {
	return ctx.Value(infoKey)
}

// WithoutInfo strips the authentication information, if any, from the provided
// context.
func WithoutInfo(ctx context.Context) context.Context {
	return context.WithValue(ctx, infoKey, nil)
}

// Errorf is a convenience function that returns an error coded with
// [connect.CodeUnauthenticated].
func Errorf(template string, args ...any) *connect.Error {
	return connect.NewError(connect.CodeUnauthenticated, fmt.Errorf(template, args...))
}

// InferProtocol returns the inferred RPC protocol. It is one of
// [connect.ProtocolConnect], [connect.ProtocolGRPC], or [connect.ProtocolGRPCWeb].
func InferProtocol(request *http.Request) string {
	ct := request.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "application/grpc-web"):
		return connect.ProtocolGRPCWeb
	case strings.HasPrefix(ct, "application/grpc"):
		return connect.ProtocolGRPC
	default:
		return connect.ProtocolConnect
	}
}

// InferProcedure returns the inferred RPC procedure. It is of the form
// "/service/method". If the request path does not contain a procedure name, the
// entire path is returned.
func InferProcedure(request *http.Request) string {
	path := strings.TrimSuffix(request.URL.Path, "/")
	ultimate := strings.LastIndex(path, "/")
	if ultimate < 0 {
		return request.URL.Path
	}
	penultimate := strings.LastIndex(path[:ultimate], "/")
	if penultimate < 0 {
		return request.URL.Path
	}
	procedure := path[penultimate:]
	if len(procedure) < 4 { // two slashes + service + method
		return request.URL.Path
	}
	return procedure
}

// Middleware is server-side HTTP middleware that authenticates RPC requests.
// In addition to rejecting unauthenticated requests, it can optionally attach
// arbitrary information about the authenticated identity to the context.
//
// Middleware operates at a lower level than Connect interceptors, so the
// server doesn't decompress and unmarshal the request until the caller has
// been authenticated.
type Middleware struct {
	auth AuthFunc
	errW *connect.ErrorWriter
}

// NewMiddleware constructs HTTP middleware using the supplied authentication
// function. If authentication succeeds, the authentication information (if
// any) will be attached to the context. Subsequent HTTP middleware, all RPC
// interceptors, and application code may access it with [GetInfo].
//
// In order to properly marshal errors, applications must pass NewMiddleware
// the same handler options used when constructing Connect handlers.
func NewMiddleware(auth AuthFunc, opts ...connect.HandlerOption) *Middleware {
	return &Middleware{
		auth: auth,
		errW: connect.NewErrorWriter(opts...),
	}
}

// Wrap returns an HTTP handler that authenticates requests before forwarding
// them to handler.
func (m *Middleware) Wrap(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ctx := request.Context()
		info, err := m.auth(ctx, request)
		if err != nil {
			_ = m.errW.Write(writer, request, err)
			return
		}
		if info != nil {
			ctx = SetInfo(ctx, info)
			request = request.WithContext(ctx)
		}
		handler.ServeHTTP(writer, request)
	})
}
