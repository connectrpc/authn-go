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
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"time"

	"connectrpc.com/authn"
	pingv1 "connectrpc.com/authn/internal/gen/authn/ping/v1"
	"connectrpc.com/authn/internal/gen/authn/ping/v1/pingv1connect"
	"connectrpc.com/connect"
)

func Example_basicAuth() {
	// This example shows how to use this package with HTTP basic authentication.
	// Any header-based authentication (including cookies and bearer tokens)
	// works similarly.

	// First, we define our authentication logic and use it to build middleware.
	authenticate := func(_ context.Context, req *http.Request) (any, error) {
		username, password, ok := req.BasicAuth()
		if !ok {
			return nil, authn.Errorf("invalid authorization")
		}
		if !equal(password, "open-sesame") {
			return nil, authn.Errorf("invalid password")
		}
		// The request is authenticated! We can propagate the authenticated user to
		// Connect interceptors and services by returning it: the middleware we're
		// about to construct will attach it to the context automatically.
		fmt.Println("authenticated request from", username)
		return username, nil
	}
	middleware := authn.NewMiddleware(authenticate)

	// Next, we build our Connect handler.
	mux := http.NewServeMux()
	service := &pingHandler{}
	mux.Handle(pingv1connect.NewPingServiceHandler(service))

	// Finally, we wrap the handler with our middleware and start our server.
	handler := middleware.Wrap(mux)
	server := httptest.NewServer(handler)
	defer server.Close()

	// Clients authenticate by setting the standard Authorization header.
	client := pingv1connect.NewPingServiceClient(http.DefaultClient, server.URL)
	req := connect.NewRequest(&pingv1.PingRequest{})
	req.Header().Set(
		"Authorization",
		"Basic "+base64.StdEncoding.EncodeToString([]byte("Aladdin:open-sesame")),
	)
	_, err := client.Ping(context.Background(), req)
	if err != nil {
		fmt.Printf("unexpected error: %v\n", err)
		return
	}
	fmt.Println("client received response")

	// Output:
	// authenticated request from Aladdin
	// client received response
}

func Example_bearerToken() {
	// This example shows how to use this package with bearer token authentication.
	// Any header-based authentication (including cookies and HTTP basic auth)
	// works similarly.

	// We'll use a simple allow list to demonstrate how to add authorization logic
	// conditionally based on the request's procedure.
	allowList := map[string]struct{}{
		// Procedure constants are available in the generated code.
		pingv1connect.PingServicePingProcedure: {},
	}
	// And a simple token-to-user map to demonstrate how to authenticate
	// requests based on a bearer token.
	tokenToUser := map[string]string{
		"open-sesame": "Aladdin",
	}

	// First, we define our authentication logic and use it to build middleware.
	authenticate := func(_ context.Context, req *http.Request) (any, error) {
		// Infer the procedure from the request URL.
		procedure, _ := authn.InferProcedure(req.URL)
		// Extract the bearer token from the Authorization header.
		token, ok := authn.BearerToken(req)
		if !ok {
			// We'll allow unauthenticated access to the ping procedure.
			if _, ok := allowList[procedure]; ok {
				fmt.Println("no authentication required for", procedure)
				return nil, nil // no authentication required
			}
			fmt.Println("authentication required for", procedure)
			err := authn.Errorf("invalid authorization")
			err.Meta().Set("WWW-Authenticate", "Bearer")
			return nil, err
		}
		user, ok := tokenToUser[token]
		if !ok {
			return nil, authn.Errorf("invalid token")
		}
		// The request is authenticated!
		fmt.Println("authenticated request from", user, "for", procedure)
		return user, nil
	}
	middleware := authn.NewMiddleware(authenticate)

	// Next, we build our Connect handler.
	mux := http.NewServeMux()
	service := &pingHandler{}
	mux.Handle(pingv1connect.NewPingServiceHandler(service))

	// Finally, we wrap the handler with our middleware and start our server.
	handler := middleware.Wrap(mux)
	server := httptest.NewServer(handler)
	defer server.Close()

	// Create an unauthenticated call to the ping procedure.
	client := pingv1connect.NewPingServiceClient(http.DefaultClient, server.URL)
	if _, err := client.Ping(context.Background(), connect.NewRequest(
		&pingv1.PingRequest{Text: "hello"},
	)); err != nil {
		fmt.Printf("unexpected error: %v\n", err)
		return
	}
	fmt.Println("client received response")

	// Create an unauthenticated call to the echo procedure.
	if _, err := client.Echo(context.Background(), connect.NewRequest(
		&pingv1.EchoRequest{Text: "hello"},
	)); connect.CodeOf(err) != connect.CodeUnauthenticated {
		fmt.Printf("unexpected error: %v\n", err)
		return
	}
	fmt.Println("client unauthorized")

	// Create an authenticated call to the echo procedure.
	req := connect.NewRequest(&pingv1.EchoRequest{Text: "hello"})
	req.Header().Set("Authorization", "Bearer open-sesame")
	if _, err := client.Echo(context.Background(), req); err != nil {
		fmt.Printf("unexpected error: %v\n", err)
		return
	}
	fmt.Println("client received response")

	// Output:
	// no authentication required for /authn.ping.v1.PingService/Ping
	// client received response
	// authentication required for /authn.ping.v1.PingService/Echo
	// client unauthorized
	// authenticated request from Aladdin for /authn.ping.v1.PingService/Echo
	// client received response
}

func Example_mutualTLS() {
	// This example shows how to use this package with mutual TLS.
	// First, we define our authentication logic and use it to build middleware.
	authenticate := func(_ context.Context, req *http.Request) (any, error) {
		tls := req.TLS
		if tls == nil {
			return nil, authn.Errorf("TLS required")
		}
		if len(tls.VerifiedChains) == 0 || len(tls.VerifiedChains[0]) == 0 {
			return nil, authn.Errorf("could not verify peer certificate")
		}
		name := tls.VerifiedChains[0][0].Subject.CommonName
		if !equal(name, "Aladdin") { // hardcode example credentials
			return nil, authn.Errorf("invalid subject common name %q", name)
		}
		// The request is authenticated! We can propagate the authenticated user to
		// Connect interceptors and services by returning it: the middleware we're
		// about to construct will attach it to the context automatically.
		fmt.Println("authenticated request from", name)
		return name, nil
	}
	middleware := authn.NewMiddleware(authenticate)

	// Next, we build our Connect handler.
	mux := http.NewServeMux()
	service := &pingv1connect.UnimplementedPingServiceHandler{}
	mux.Handle(pingv1connect.NewPingServiceHandler(service))

	// Finally, we wrap the handler with our middleware and start the server.
	// Creating server and client TLS configurations is particularly verbose in
	// examples, where we need to set up a complete self-signed chain of trust.
	clientTLS, serverTLS, err := newTLSConfigs("Aladdin", "Cave of Wonders")
	if err != nil {
		fmt.Printf("error creating TLS configs: %v\n", err)
		return
	}
	handler := middleware.Wrap(mux)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()

	// Clients must configure their underlying HTTP clients to present a valid
	// certificate.
	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLS},
	}
	client := pingv1connect.NewPingServiceClient(httpClient, server.URL)
	_, err = client.Ping(
		context.Background(),
		connect.NewRequest(&pingv1.PingRequest{}),
	)

	// We're using the UnimplementedPingServiceHandler stub, so authenticated
	// clients should receive an error with CodeUnimplemented.
	if connect.CodeOf(err) == connect.CodeUnimplemented {
		fmt.Println("client received response")
	} else {
		fmt.Printf("unexpected error: %v\n", err)
	}

	// Output:
	// authenticated request from Aladdin
	// client received response
}

func newTLSConfigs(clientName, serverName string) (client *tls.Config, server *tls.Config, _ error) {
	caCertPEM, caKeyPEM, err := createCertificateAuthority()
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate authority: %w", err)
	}
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
		return nil, nil, errors.New("failed to append certs to pool")
	}
	serverCertificate, err := newCertificate(caCertPEM, caKeyPEM, serverName)
	if err != nil {
		return nil, nil, fmt.Errorf("create server certificate: %w", err)
	}
	clientCertificate, err := newCertificate(caCertPEM, caKeyPEM, clientName)
	if err != nil {
		return nil, nil, fmt.Errorf("create client certificate: %w", err)
	}
	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientCertificate},
		RootCAs:      certPool,
		MinVersion:   tls.VersionTLS12,
	}
	serverTLS := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{serverCertificate},
		ClientCAs:    certPool,
		MinVersion:   tls.VersionTLS12,
	}
	return clientTLS, serverTLS, nil
}

func createCertificateAuthority() ([]byte, []byte, error) {
	caCert := &x509.Certificate{
		SerialNumber: big.NewInt(2021),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	caPrivKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	return caPEM, caPrivKeyPEM, nil
}

func newCertificate(caCertPEM, caKeyPEM []byte, commonName string) (tls.Certificate, error) {
	keyPEMBlock, _ := pem.Decode(caKeyPEM)
	privateKey, err := x509.ParsePKCS1PrivateKey(keyPEMBlock.Bytes)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEMBlock, _ := pem.Decode(caCertPEM)
	parent, err := x509.ParseCertificate(certPEMBlock.Bytes)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
			CommonName:   commonName,
		},
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
			net.IPv6loopback,
			net.IPv4(0, 0, 0, 0),
			net.IPv6zero,
		},
		NotBefore:    time.Now().AddDate(-1, 0, 0),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return tls.Certificate{}, err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, parent, &certPrivKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	certPrivKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	return tls.X509KeyPair(certPEM, certPrivKeyPEM)
}

func equal(left, right string) bool {
	// Using subtle prevents some timing attacks.
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

type pingHandler struct {
	pingv1connect.UnimplementedPingServiceHandler
}

func (pingHandler) Ping(_ context.Context, req *connect.Request[pingv1.PingRequest]) (*connect.Response[pingv1.PingResponse], error) {
	return connect.NewResponse(&pingv1.PingResponse{Text: req.Msg.Text}), nil
}

func (pingHandler) Echo(_ context.Context, req *connect.Request[pingv1.EchoRequest]) (*connect.Response[pingv1.EchoResponse], error) {
	return connect.NewResponse(&pingv1.EchoResponse{Text: req.Msg.Text}), nil
}

func (pingHandler) PingStream(_ context.Context, stream *connect.BidiStream[pingv1.PingStreamRequest, pingv1.PingStreamResponse]) error {
	for {
		req, err := stream.Receive()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := stream.Send(&pingv1.PingStreamResponse{Text: req.Text}); err != nil {
			return err
		}
	}
}
