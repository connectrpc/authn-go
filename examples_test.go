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
	"log"
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
	// This example demonstrates how to use basic auth with the authn middleware.
	// The example uses the ping service from the
	// connectrpc.com/authn/internal/gen/authn/ping/v1 package, but the same
	// approach can be used with any service.
	mux := http.NewServeMux()
	mux.Handle(pingv1connect.NewPingServiceHandler(pingService{}))

	// Wrap the server with authn middleware.
	auth := authn.NewMiddleware(
		func(_ context.Context, req authn.Request) (any, error) {
			username, password, ok := req.BasicAuth()
			if !ok {
				// If authentication fails, we return an error. authn.Errorf is a
				// convenient shortcut to produce an error coded with
				// connect.CodeUnauthenticated.
				return nil, authn.Errorf("invalid authorization")
			}
			// Check username and password against a database. In this example, we
			// hardcode the credentials.
			if subtle.ConstantTimeCompare([]byte(username), []byte("Ali Baba")) != 1 {
				return nil, authn.Errorf("invalid username")
			}
			if subtle.ConstantTimeCompare([]byte(password), []byte("opensesame")) != 1 {
				return nil, authn.Errorf("invalid password")
			}
			// Once we've authenticated the request, we can return some information about
			// the client. That information gets attached to the context passed to
			// subsequent interceptors and our service implementation.
			fmt.Printf("verified user: %s\n", username)
			return username, nil
		},
	)
	handler := auth.Wrap(mux)

	// Start the server.
	server := httptest.NewServer(handler)
	defer server.Close()

	// Create a client for the server.
	client := pingv1connect.NewPingServiceClient(
		server.Client(),
		server.URL,
	)
	req := connect.NewRequest(&pingv1.PingRequest{
		Text: "hello",
	})
	// Attach a basic auth authorization header to the request.
	authToken := base64.StdEncoding.EncodeToString([]byte("Ali Baba:opensesame"))
	req.Header().Add("Authorization", "Basic "+authToken)
	rsp, err := client.Ping(context.Background(), req)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("got response: %s\n", rsp.Msg.Text)
	// Output:
	// verified user: Ali Baba
	// got response: hello
}

func Example_mutualTLS() {
	// This example demonstrates how to use mutual TLS with the authn middleware.
	// The example uses the ping service from the
	// connectrpc.com/authn/internal/gen/authn/ping/v1 package, but the same
	// approach can be used with any service.

	// Create the certificate authority. The server and client will both use this
	// certificate authority to verify each other's certificates.
	//
	// This example uses a self-signed certificate, so
	// we need to use a custom root CA pool. In production, you would use a
	// certificate signed by a trusted CA.
	certPool := x509.NewCertPool()
	caCertPEM, caKeyPEM, err := createCertificateAuthority()
	if err != nil {
		log.Fatal(err)
	}
	if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
		log.Fatal("failed to append certs to pool")
	}

	// Create the server certificate. The server will use this certificate to
	// authenticate itself to the client. We will need to create a custom TLS
	// configuration for the server to use this certificate.
	certPEM, keyPEM, err := createCertificate(caCertPEM, caKeyPEM, "Server")
	if err != nil {
		log.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    certPool,
		MinVersion:   tls.VersionTLS12,
	}

	mux := http.NewServeMux()
	mux.Handle(pingv1connect.NewPingServiceHandler(pingService{}))

	// Wrap the server with authn middleware.
	auth := authn.NewMiddleware(
		func(_ context.Context, req authn.Request) (any, error) {
			// Get the TLS connection state from the request.
			tls := req.TLS()
			if tls == nil {
				return nil, authn.Errorf("requires TLS certificate")
			}
			if len(tls.VerifiedChains) == 0 || len(tls.VerifiedChains[0]) == 0 {
				return nil, authn.Errorf("could not verify peer certificate")
			}
			// Check subject common name against configured username.
			// In this example, we hardcode the username.
			commonName := tls.VerifiedChains[0][0].Subject.CommonName
			if commonName != "Client" {
				return nil, authn.Errorf("invalid subject common name")
			}
			fmt.Printf("verified peer certificate: %s\n", commonName)
			return commonName, nil
		},
	)
	handler := auth.Wrap(mux)

	// Start the server with TLS.
	server := httptest.NewUnstartedServer(handler)
	server.TLS = tlsConfig
	server.StartTLS()
	defer server.Close()

	// Create the client certificate. The client will use this certificate to
	// authenticate itself to the server. We will need to create a custom TLS
	// configuration for the client to use this certificate.
	certPEM, keyPEM, err = createCertificate(caCertPEM, caKeyPEM, "Client")
	if err != nil {
		log.Fatal(err)
	}
	certificate, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	tlsClientConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      certPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Create the client with the client certificate.
	client := pingv1connect.NewPingServiceClient(
		&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsClientConfig,
			},
		},
		server.URL,
	)

	// Make a request with the created client.
	req := connect.NewRequest(&pingv1.PingRequest{
		Text: "hello",
	})
	rsp, err := client.Ping(context.Background(), req)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("got response: %s\n", rsp.Msg.Text)
	// Output:
	// verified peer certificate: Client
	// got response: hello
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

func createCertificate(caCertPEM, caKeyPEM []byte, commonName string) ([]byte, []byte, error) {
	keyPEMBlock, _ := pem.Decode(caKeyPEM)
	privateKey, err := x509.ParsePKCS1PrivateKey(keyPEMBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	certPEMBlock, _ := pem.Decode(caCertPEM)
	parent, err := x509.ParseCertificate(certPEMBlock.Bytes)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, parent, &certPrivKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	certPrivKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	return certPEM, certPrivKeyPEM, nil
}

type pingService struct{}

func (pingService) Ping(_ context.Context, req *connect.Request[pingv1.PingRequest]) (*connect.Response[pingv1.PingResponse], error) {
	return connect.NewResponse(&pingv1.PingResponse{
		Text: req.Msg.Text,
	}), nil
}

func (pingService) PingStream(_ context.Context, stream *connect.BidiStream[pingv1.PingStreamRequest, pingv1.PingStreamResponse]) error {
	for {
		req, err := stream.Receive()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := stream.Send(&pingv1.PingStreamResponse{
			Text: req.Text,
		}); err != nil {
			return err
		}
	}
}
