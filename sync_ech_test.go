package reality

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

const syncECHVersion = uint16(0xfe0d)

func syncBuildECHConfig(t *testing.T) (configList, privateKey []byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	configBuilder := cryptobyte.NewBuilder(nil)
	configBuilder.AddUint16(syncECHVersion)
	configBuilder.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(7) // Config ID.
		b.AddUint16(0x0020)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(key.PublicKey().Bytes())
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(0x0001) // HKDF-SHA256.
			b.AddUint16(0x0001) // AES-128-GCM.
		})
		b.AddUint8(64)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes([]byte("public.example"))
		})
		b.AddUint16(0) // No ECHConfig extensions.
	})
	config, err := configBuilder.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	listBuilder := cryptobyte.NewBuilder(nil)
	listBuilder.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(config)
	})
	list, err := listBuilder.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return list, key.Bytes()
}

func syncECHRealityClient(list []byte, roots *x509.CertPool) *Config {
	return &Config{
		ServerName:                     "secret.example",
		RootCAs:                        roots,
		MinVersion:                     VersionTLS13,
		MaxVersion:                     VersionTLS13,
		EncryptedClientHelloConfigList: list,
	}
}

func syncECHStandardClient(list []byte, roots *x509.CertPool) *stdtls.Config {
	return &stdtls.Config{
		ServerName:                     "secret.example",
		RootCAs:                        roots,
		MinVersion:                     stdtls.VersionTLS13,
		MaxVersion:                     stdtls.VersionTLS13,
		EncryptedClientHelloConfigList: list,
	}
}

func syncECHRealityServer(publicCert, secretCert syncCertificate, config, privateKey []byte, enabled bool) *Config {
	server := &Config{
		Certificates: []Certificate{publicCert.reality, secretCert.reality},
		MinVersion:   VersionTLS13,
		MaxVersion:   VersionTLS13,
	}
	if enabled {
		server.EncryptedClientHelloKeys = []EncryptedClientHelloKey{{
			Config:      config,
			PrivateKey:  privateKey,
			SendAsRetry: true,
		}}
	}
	return server
}

func syncECHStandardServer(publicCert, secretCert syncCertificate, config, privateKey []byte, enabled bool) *stdtls.Config {
	server := &stdtls.Config{
		Certificates: []stdtls.Certificate{publicCert.std, secretCert.std},
		MinVersion:   stdtls.VersionTLS13,
		MaxVersion:   stdtls.VersionTLS13,
	}
	if enabled {
		server.EncryptedClientHelloKeys = []stdtls.EncryptedClientHelloKey{{
			Config:      config,
			PrivateKey:  privateKey,
			SendAsRetry: true,
		}}
	}
	return server
}

func syncHandshakeOnly(t *testing.T, client, server syncTLSConn, pair syncTransportPair) (clientErr, serverErr error) {
	t.Helper()
	deadline := time.Now().Add(syncHandshakeTimeout)
	if err := pair.client.SetDeadline(deadline); err != nil {
		return err, nil
	}
	if err := pair.server.SetDeadline(deadline); err != nil {
		return err, nil
	}
	serverDone := make(chan error, 1)
	clientDone := make(chan error, 1)
	go func() {
		serverDone <- server.Handshake()
	}()
	go func() {
		clientDone <- client.Handshake()
	}()
	deadlineTimer := time.NewTimer(syncHandshakeTimeout)
	defer deadlineTimer.Stop()
	for clientDone != nil || serverDone != nil {
		select {
		case clientErr = <-clientDone:
			clientDone = nil
			// ECH rejection sends an alert after the TLS handshake. A net.Pipe
			// peer that has already returned would otherwise leave that write
			// blocked until the transport deadline.
			pair.close()
		case serverErr = <-serverDone:
			serverDone = nil
			pair.close()
		case <-deadlineTimer.C:
			pair.close()
			return context.DeadlineExceeded, context.DeadlineExceeded
		}
	}
	return clientErr, serverErr
}

func TestSyncECHAcceptance(t *testing.T) {
	cases := []struct {
		name          string
		realityClient bool
		realityServer bool
	}{
		{"RealityToReality", true, true},
		{"RealityToStandard", true, false},
		{"StandardToReality", false, true},
		{"StandardToStandard", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			publicCert := syncNewECHCertificate(t, "public.example")
			secretCert := syncNewECHCertificate(t, "secret.example")
			configList, privateKey := syncBuildECHConfig(t)
			roots := syncRootCAs(publicCert, secretCert)
			pair := syncNewTransportPair(t, false)

			var client, server syncTLSConn
			if tc.realityClient {
				client = Client(pair.client, syncECHRealityClient(configList, roots))
			} else {
				client = stdtls.Client(pair.client, syncECHStandardClient(configList, roots))
			}
			if tc.realityServer {
				server = serverConn(pair.server, syncECHRealityServer(publicCert, secretCert, configList[2:], privateKey, true))
			} else {
				server = stdtls.Server(pair.server, syncECHStandardServer(publicCert, secretCert, configList[2:], privateKey, true))
			}
			defer func() {
				pair.close()
				client.Close()
				server.Close()
			}()
			if err := syncRunTLSExchange(t, client, server, pair); err != nil {
				t.Fatal(err)
			}

			var clientState ConnectionState
			var standardClientState stdtls.ConnectionState
			if tc.realityClient {
				clientState = client.(*Conn).ConnectionState()
			} else {
				standardClientState = client.(*stdtls.Conn).ConnectionState()
			}
			var serverState ConnectionState
			var standardServerState stdtls.ConnectionState
			if tc.realityServer {
				serverState = server.(*Conn).ConnectionState()
			} else {
				standardServerState = server.(*stdtls.Conn).ConnectionState()
			}
			if tc.realityClient {
				if !clientState.ECHAccepted || clientState.ServerName != "secret.example" {
					t.Fatalf("reality client state = ECHAccepted:%v ServerName:%q", clientState.ECHAccepted, clientState.ServerName)
				}
			} else if !standardClientState.ECHAccepted || standardClientState.ServerName != "secret.example" {
				t.Fatalf("standard client state = ECHAccepted:%v ServerName:%q", standardClientState.ECHAccepted, standardClientState.ServerName)
			}
			if tc.realityServer {
				if !serverState.ECHAccepted || serverState.ServerName != "secret.example" {
					t.Fatalf("reality server state = ECHAccepted:%v ServerName:%q", serverState.ECHAccepted, serverState.ServerName)
				}
			} else if !standardServerState.ECHAccepted || standardServerState.ServerName != "secret.example" {
				t.Fatalf("standard server state = ECHAccepted:%v ServerName:%q", standardServerState.ECHAccepted, standardServerState.ServerName)
			}
		})
	}
}

func TestSyncECHRejection(t *testing.T) {
	cases := []struct {
		name          string
		realityClient bool
		realityServer bool
	}{
		{"RealityToReality", true, true},
		{"RealityToStandard", true, false},
		{"StandardToReality", false, true},
		{"StandardToStandard", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			publicCert := syncNewECHCertificate(t, "public.example")
			secretCert := syncNewECHCertificate(t, "secret.example")
			configList, privateKey := syncBuildECHConfig(t)
			roots := syncRootCAs(publicCert, secretCert)
			pair := syncNewTransportPair(t, false)
			var client, server syncTLSConn
			if tc.realityClient {
				client = Client(pair.client, syncECHRealityClient(configList, roots))
			} else {
				client = stdtls.Client(pair.client, syncECHStandardClient(configList, roots))
			}
			if tc.realityServer {
				server = serverConn(pair.server, syncECHRealityServer(publicCert, secretCert, configList[2:], privateKey, false))
			} else {
				server = stdtls.Server(pair.server, syncECHStandardServer(publicCert, secretCert, configList[2:], privateKey, false))
			}
			clientErr, _ := syncHandshakeOnly(t, client, server, pair)
			if clientErr == nil {
				t.Fatal("ECH handshake unexpectedly succeeded without a server key")
			}
			if tc.realityClient {
				var rejection *ECHRejectionError
				if !errors.As(clientErr, &rejection) {
					t.Fatalf("client error = %v, want ECHRejectionError", clientErr)
				}
				if len(rejection.RetryConfigList) != 0 {
					t.Fatalf("reality RetryConfigList length = %d, want 0", len(rejection.RetryConfigList))
				}
			} else {
				var rejection *stdtls.ECHRejectionError
				if !errors.As(clientErr, &rejection) {
					t.Fatalf("client error = %v, want standard ECHRejectionError", clientErr)
				}
				if len(rejection.RetryConfigList) != 0 {
					t.Fatalf("standard RetryConfigList length = %d, want 0", len(rejection.RetryConfigList))
				}
			}
		})
	}
}

func TestSyncECHConfigEncoding(t *testing.T) {
	configList, privateKey := syncBuildECHConfig(t)
	if len(configList) < 8 || len(privateKey) != 32 {
		t.Fatalf("ECH fixture lengths = config %d, private key %d", len(configList), len(privateKey))
	}
	if got := fmt.Sprintf("%x", configList[:2]); got != "0041" {
		t.Fatalf("ECHConfigList length prefix = %s, want 0041", got)
	}
	if _, err := ecdh.X25519().NewPrivateKey(privateKey); err != nil {
		t.Fatalf("generated ECH private key is invalid: %v", err)
	}
}
