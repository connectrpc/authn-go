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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/bufbuild/authn-go"
	pingv1 "github.com/bufbuild/authn-go/internal/gen/authn/ping/v1"
	"github.com/bufbuild/authn-go/internal/gen/authn/ping/v1/pingv1connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Example_mutualTLS() {
	log := log.New(os.Stdout, "" /* prefix */, 0 /* flags */)
	certPool := x509.NewCertPool()
	caCertPEM, caKeyPEM, err := createCertificateAuthority()
	if err != nil {
		log.Fatal(err)
	}
	if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
		log.Fatal("failed to append client certs")
	}

	// Create the server certificate.
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
	}

	mux := http.NewServeMux()
	mux.Handle(pingv1connect.NewPingServiceHandler(pingService{}))

	// Wrap the server with authn middleware.
	auth := authn.NewMiddleware(
		func(ctx context.Context, req authn.Request) (any, error) {
			if req.TLS == nil {
				return nil, fmt.Errorf("no TLS connection state")
			}
			if len(req.TLS.VerifiedChains) == 0 || len(req.TLS.VerifiedChains[0]) == 0 {
				return nil, authn.Errorf("could not verify peer certificate")
			}
			// Check subject common name against configured username
			commonName := req.TLS.VerifiedChains[0][0].Subject.CommonName
			if commonName != "Client" {
				return nil, authn.Errorf("invalid subject common name")
			}
			log.Printf("verified peer certificate: %s", commonName)
			return commonName, nil
		},
	)
	handler := auth.Wrap(mux)

	// Start the server with TLS.
	server := httptest.NewUnstartedServer(handler)
	server.TLS = tlsConfig
	server.StartTLS()
	defer server.Close()

	// Create the client certificate.
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
	}

	// Create the client.
	client := pingv1connect.NewPingServiceClient(
		&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsClientConfig,
			},
		},
		server.URL,
	)

	// Make a request.
	req := connect.NewRequest(&pingv1.PingRequest{
		Text: "hello",
	})
	rsp, err := client.Ping(context.Background(), req)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("got response: %s", rsp.Msg.Text)
	// Output:
	// verified peer certificate: Client
	// got response: hello
}

func TestTLSServer(t *testing.T) {
	ctx := context.Background()

	// certPool
	certPool := x509.NewCertPool()
	caCertPEM, caKeyPEM, err := createCertificateAuthority()
	if err != nil {
		t.Fatal(err)
	}
	if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
		t.Fatal("failed to append client certs")
	}

	// Create the server certificate.
	certPEM, keyPEM, err := createCertificate(caCertPEM, caKeyPEM, "Server")
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    certPool,
	}

	mux := http.NewServeMux()
	mux.Handle(pingv1connect.NewPingServiceHandler(pingService{}))

	auth := authn.NewMiddleware(
		func(ctx context.Context, req authn.Request) (any, error) {
			if req.TLS == nil {
				return nil, fmt.Errorf("no TLS connection state")
			}
			if len(req.TLS.VerifiedChains) == 0 || len(req.TLS.VerifiedChains[0]) == 0 {
				return nil, authn.Errorf("could not verify peer certificate")
			}
			// Check subject common name against configured username
			commonName := req.TLS.VerifiedChains[0][0].Subject.CommonName
			if commonName != "Client" {
				return nil, authn.Errorf("invalid subject common name")
			}
			return commonName, nil
		},
	)
	handler := auth.Wrap(mux)

	server := httptest.NewUnstartedServer(handler)
	server.TLS = tlsConfig
	server.StartTLS()
	t.Cleanup(server.Close)

	certPEM, keyPEM, err = createCertificate(caCertPEM, caKeyPEM, "Client")
	if err != nil {
		t.Fatal(err)
	}
	certificate, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      certPool,
	}
	tlsInsecure := &tls.Config{
		InsecureSkipVerify: true,
	}

	t.Run("secure", func(t *testing.T) {
		client := pingv1connect.NewPingServiceClient(
			&http.Client{
				Transport: &http.Transport{
					TLSClientConfig: tlsConfig,
				},
			},
			server.URL,
		)
		req := connect.NewRequest(&pingv1.PingRequest{
			Text: "hello",
		})
		rsp, err := client.Ping(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, "hello", rsp.Msg.Text)
	})
	t.Run("insecure", func(t *testing.T) {
		client := pingv1connect.NewPingServiceClient(
			&http.Client{
				Transport: &http.Transport{
					TLSClientConfig: tlsInsecure,
				},
			},
			server.URL,
		)
		req := connect.NewRequest(&pingv1.PingRequest{
			Text: "hello",
		})
		_, err := client.Ping(ctx, req)
		require.ErrorContains(t, err, "tls: certificate required")
	})
}

func createCertificateAuthority() ([]byte, []byte, error) {
	ca := &x509.Certificate{
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
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}
	caPEM := new(bytes.Buffer)
	if err := pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}); err != nil {
		return nil, nil, err
	}
	caPrivKeyPEM := new(bytes.Buffer)
	if err := pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	}); err != nil {
		return nil, nil, err
	}
	return caPEM.Bytes(), caPrivKeyPEM.Bytes(), nil
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
	certPEM := new(bytes.Buffer)
	if err := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		return nil, nil, err
	}
	certPrivKeyPEM := new(bytes.Buffer)
	if err := pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	}); err != nil {
		return nil, nil, err
	}
	return certPEM.Bytes(), certPrivKeyPEM.Bytes(), nil
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
