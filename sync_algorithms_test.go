package reality

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestSyncKeyExchangeInteroperability(t *testing.T) {
	cert := syncNewCertificate(t, "localhost")
	for _, group := range curvePreferenceOrder() {
		for _, forkClient := range []bool{false, true} {
			role := "server"
			if forkClient {
				role = "client"
			}
			t.Run(group.String()+"/"+role, func(t *testing.T) {
				pair := syncNewTransportPair(t, false)
				defer pair.close()
				forkConfig := &Config{
					Certificates: []Certificate{cert.reality}, RootCAs: syncRootCAs(cert),
					ServerName: "localhost", MinVersion: VersionTLS13,
					CurvePreferences: []CurveID{group}, NextProtos: []string{"h2"},
				}
				stdConfig := &stdtls.Config{
					Certificates: []stdtls.Certificate{cert.std}, RootCAs: syncRootCAs(cert),
					ServerName: "localhost", MinVersion: stdtls.VersionTLS13,
					CurvePreferences: []stdtls.CurveID{stdtls.CurveID(group)}, NextProtos: []string{"h2"},
				}
				var fork *Conn
				var std *stdtls.Conn
				var client, server syncTLSConn
				if forkClient {
					fork, std = Client(pair.client, forkConfig), stdtls.Server(pair.server, stdConfig)
					client, server = fork, std
				} else {
					fork, std = serverConn(pair.server, forkConfig), stdtls.Client(pair.client, stdConfig)
					client, server = std, fork
				}
				if err := syncRunTLSExchange(t, client, server, pair); err != nil {
					t.Fatal(err)
				}
				if got := fork.ConnectionState().CurveID; got != group {
					t.Fatalf("negotiated group = %s, want %s", got, group)
				}
				if fork.ConnectionState().NegotiatedProtocol != "h2" || std.ConnectionState().NegotiatedProtocol != "h2" {
					t.Fatal("ALPN was not negotiated")
				}
			})
		}
	}
}

func TestSyncMLDSACertificateInteroperability(t *testing.T) {
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		key, err := mldsa.GenerateKey(params)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(leaf)
		for _, forkClient := range []bool{false, true} {
			role := "server"
			if forkClient {
				role = "client"
			}
			t.Run(leaf.SignatureAlgorithm.String()+"/"+role, func(t *testing.T) {
				pair := syncNewTransportPair(t, false)
				defer pair.close()
				forkConfig := &Config{
					Certificates: []Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
					ServerName:   "localhost", RootCAs: roots, MinVersion: VersionTLS13,
					ClientAuth: RequireAndVerifyClientCert, ClientCAs: roots,
				}
				stdConfig := &stdtls.Config{
					Certificates: []stdtls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
					ServerName:   "localhost", RootCAs: roots, MinVersion: stdtls.VersionTLS13,
					ClientAuth: stdtls.RequireAndVerifyClientCert, ClientCAs: roots,
				}
				var client, server syncTLSConn
				if forkClient {
					client, server = Client(pair.client, forkConfig), stdtls.Server(pair.server, stdConfig)
				} else {
					client, server = stdtls.Client(pair.client, stdConfig), serverConn(pair.server, forkConfig)
				}
				if err := syncRunTLSExchange(t, client, server, pair); err != nil {
					t.Fatal(err)
				}
				for _, conn := range []syncTLSConn{client, server} {
					if fork, ok := conn.(*Conn); ok {
						local := fork.ConnectionState().LocalCertificate
						if len(local) != 1 || !bytes.Equal(local[0], der) {
							t.Fatal("LocalCertificate does not contain the sent ML-DSA certificate")
						}
					}
				}
			})
		}
	}
}
