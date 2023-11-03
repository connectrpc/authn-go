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

// Package authn provides authentication middleware for [connect].
package authn

import (
	"context"
	"crypto/tls"
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
// return some information about the authenticated caller (or nil).
// Implementations must be safe to call concurrently.
type AuthFunc func(ctx context.Context, req Request) (any, error)

// SetInfo attaches authentication information to the context. It's often
// useful in tests.
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

// Request describes a single RPC invocation.
type Request struct {
	request *http.Request
}

// BasicAuth returns the username and password provided in the request's
// Authorization header, if any.
func (r Request) BasicAuth() (username string, password string, ok bool) {
	return r.request.BasicAuth()
}

// Procedure returns the RPC procedure name, in the form "/service/method". If
// the request path does not contain a procedure name, the entire path is
// returned.
func (r Request) Procedure() string {
	path := strings.TrimSuffix(r.request.URL.Path, "/")
	ultimate := strings.LastIndex(path, "/")
	if ultimate < 0 {
		return r.request.URL.Path
	}
	penultimate := strings.LastIndex(path[:ultimate], "/")
	if penultimate < 0 {
		return r.request.URL.Path
	}
	procedure := path[penultimate:]
	if len(procedure) < 4 { // two slashes + service + method
		return r.request.URL.Path
	}
	return procedure
}

// ClientAddr returns the client address, in IP:port format.
func (r Request) ClientAddr() string {
	return r.request.RemoteAddr
}

// Protocol returns the RPC protocol. It is one of connect.ProtocolConnect,
// connect.ProtocolGRPC, or connect.ProtocolGRPCWeb.
func (r Request) Protocol() string {
	ct := r.request.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "application/grpc-web"):
		return connect.ProtocolGRPCWeb
	case strings.HasPrefix(ct, "application/grpc"):
		return connect.ProtocolGRPC
	default:
		return connect.ProtocolConnect
	}
}

// Header returns the HTTP request headers.
func (r Request) Header() http.Header {
	return r.request.Header
}

// TLS returns the TLS connection state, if any. It may be nil if the connection
// is not using TLS.
func (r Request) TLS() *tls.ConnectionState {
	return r.request.TLS
}

// Middleware is server-side HTTP middleware that authenticates RPC requests.
// In addition to rejecting unauthenticated requests, it can optionally attach
// arbitrary information to the context of authenticated requests. Any non-RPC
// requests (as determined by their Content-Type) are forwarded directly to the
// wrapped handler without authentication.
//
// Middleware operates at a lower level than [Interceptor]. For most
// applications, Middleware is preferable because it defers decompressing and
// unmarshaling the request until after the caller has been authenticated.
type Middleware struct {
	auth AuthFunc
	errW *connect.ErrorWriter
}

// NewMiddleware constructs HTTP middleware using the supplied authentication
// function. If authentication succeeds, the authentication information (if
// any) will be attached to the context. Subsequent HTTP middleware, all RPC
// interceptors, and application code may access it with [GetInfo].
//
// In order to properly identify RPC requests and marshal errors, applications
// must pass NewMiddleware the same handler options used when constructing
// Connect handlers.
func NewMiddleware(auth AuthFunc, opts ...connect.HandlerOption) *Middleware {
	return &Middleware{
		auth: auth,
		errW: connect.NewErrorWriter(opts...),
	}
}

// Wrap returns an HTTP handler that authenticates RPC requests before
// forwarding them to handler. If handler is not an RPC request, it is forwarded
// directly, without authentication.
func (m *Middleware) Wrap(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !m.errW.IsSupported(request) {
			handler.ServeHTTP(writer, request)
			return // not an RPC request
		}
		ctx := request.Context()
		info, err := m.auth(ctx, Request{request: request})
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
