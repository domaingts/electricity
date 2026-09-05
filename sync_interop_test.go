package reality

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

const syncHandshakeTimeout = 5 * time.Second

type syncCertificate struct {
	der     []byte
	parsed  *x509.Certificate
	std     stdtls.Certificate
	reality Certificate
}

func syncNewCertificate(t *testing.T, dnsName string) syncCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 96))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return syncCertificate{
		der:    der,
		parsed: parsed,
		std: stdtls.Certificate{
			Certificate: [][]byte{der},
			PrivateKey:  key,
			Leaf:        parsed,
		},
		reality: Certificate{
			Certificate: [][]byte{der},
			PrivateKey:  key,
			Leaf:        parsed,
		},
	}
}

func syncNewECHCertificate(t *testing.T, dnsName string) syncCertificate {
	return syncNewCertificate(t, dnsName)
}

func syncRootCAs(certs ...syncCertificate) *x509.CertPool {
	roots := x509.NewCertPool()
	for _, cert := range certs {
		roots.AddCert(cert.parsed)
	}
	return roots
}

type syncTransportPair struct {
	client   net.Conn
	server   net.Conn
	listener net.Listener
}

func syncNewTransportPair(t *testing.T, loopback bool) syncTransportPair {
	t.Helper()
	if !loopback {
		client, server := net.Pipe()
		return syncTransportPair{client: client, server: server}
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, err := listener.Accept()
		accepted <- struct {
			conn net.Conn
			err  error
		}{conn, err}
	}()
	client, err := net.DialTimeout("tcp", listener.Addr().String(), syncHandshakeTimeout)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	var result struct {
		conn net.Conn
		err  error
	}
	select {
	case result = <-accepted:
	case <-time.After(syncHandshakeTimeout):
		client.Close()
		listener.Close()
		t.Fatal("timed out accepting loopback connection")
	}
	if result.err != nil {
		client.Close()
		listener.Close()
		t.Fatal(result.err)
	}
	return syncTransportPair{client: client, server: result.conn, listener: listener}
}

func (p syncTransportPair) close() {
	if p.client != nil {
		p.client.Close()
	}
	if p.server != nil {
		p.server.Close()
	}
	if p.listener != nil {
		p.listener.Close()
	}
}

type syncTLSConn interface {
	Handshake() error
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

func syncRunTLSExchange(t *testing.T, client, server syncTLSConn, pair syncTransportPair) error {
	t.Helper()
	deadline := time.Now().Add(syncHandshakeTimeout)
	if err := pair.client.SetDeadline(deadline); err != nil {
		return err
	}
	if err := pair.server.SetDeadline(deadline); err != nil {
		return err
	}

	serverDone := make(chan error, 1)
	go func() {
		if err := server.Handshake(); err != nil {
			serverDone <- err
			return
		}
		var got [4]byte
		if _, err := io.ReadFull(server, got[:]); err != nil {
			serverDone <- err
			return
		}
		if string(got[:]) != "ping" {
			serverDone <- fmt.Errorf("server received %q, want ping", got[:])
			return
		}
		_, err := server.Write([]byte("pong"))
		serverDone <- err
	}()

	if err := client.Handshake(); err != nil {
		pair.close()
		select {
		case serverErr := <-serverDone:
			return fmt.Errorf("client handshake: %w (server: %v)", err, serverErr)
		case <-time.After(syncHandshakeTimeout):
			return fmt.Errorf("client handshake: %w; server did not stop", err)
		}
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		pair.close()
		return fmt.Errorf("client write: %w", err)
	}
	var got [4]byte
	if _, err := io.ReadFull(client, got[:]); err != nil {
		pair.close()
		return fmt.Errorf("client read: %w", err)
	}
	if string(got[:]) != "pong" {
		pair.close()
		return fmt.Errorf("client received %q, want pong", got[:])
	}
	select {
	case err := <-serverDone:
		return err
	case <-time.After(syncHandshakeTimeout):
		return errors.New("server exchange did not complete")
	}
}

func syncRealityClient(pair syncTransportPair, cert syncCertificate, version uint16) *Conn {
	return Client(pair.client, &Config{
		Certificates:       []Certificate{cert.reality},
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
	})
}

func syncStandardClient(pair syncTransportPair, cert syncCertificate, version uint16) *stdtls.Conn {
	return stdtls.Client(pair.client, &stdtls.Config{
		Certificates:       []stdtls.Certificate{cert.std},
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
	})
}

func syncRealityServer(pair syncTransportPair, cert syncCertificate, version uint16) *Conn {
	return serverConn(pair.server, &Config{
		Certificates: []Certificate{cert.reality},
		MinVersion:   version,
		MaxVersion:   version,
	})
}

func syncStandardServer(pair syncTransportPair, cert syncCertificate, version uint16) *stdtls.Conn {
	return stdtls.Server(pair.server, &stdtls.Config{
		Certificates: []stdtls.Certificate{cert.std},
		MinVersion:   version,
		MaxVersion:   version,
	})
}

func TestSyncOrdinaryTLSInteroperability(t *testing.T) {
	// Keep this matrix explicit: it covers both implementations in both roles,
	// both TLS versions, and both transports used by the package's callers.
	cases := []struct {
		name          string
		version       uint16
		realityClient bool
		loopback      bool
	}{
		{"TLS12RealityClientPipe", VersionTLS12, true, false},
		{"TLS12RealityClientLoopback", VersionTLS12, true, true},
		{"TLS12StandardClientPipe", VersionTLS12, false, false},
		{"TLS12StandardClientLoopback", VersionTLS12, false, true},
		{"TLS13RealityClientPipe", VersionTLS13, true, false},
		{"TLS13RealityClientLoopback", VersionTLS13, true, true},
		{"TLS13StandardClientPipe", VersionTLS13, false, false},
		{"TLS13StandardClientLoopback", VersionTLS13, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert := syncNewCertificate(t, "localhost")
			pair := syncNewTransportPair(t, tc.loopback)

			var client, server syncTLSConn
			if tc.realityClient {
				client = syncRealityClient(pair, cert, tc.version)
				server = syncStandardServer(pair, cert, tc.version)
			} else {
				client = syncStandardClient(pair, cert, tc.version)
				server = syncRealityServer(pair, cert, tc.version)
			}
			defer func() {
				pair.close()
				client.Close()
				server.Close()
			}()
			if err := syncRunTLSExchange(t, client, server, pair); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type syncRealitySessionCache struct {
	mu    sync.Mutex
	items map[string]*ClientSessionState
	puts  int
	gets  int
}

func (c *syncRealitySessionCache) Get(key string) (*ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gets++
	state, ok := c.items[key]
	return state, ok
}

func (c *syncRealitySessionCache) Put(key string, state *ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.puts++
	if state == nil {
		delete(c.items, key)
		return
	}
	c.items[key] = state
}

type syncStandardSessionCache struct {
	mu    sync.Mutex
	items map[string]*stdtls.ClientSessionState
	puts  int
	gets  int
}

func (c *syncStandardSessionCache) Get(key string) (*stdtls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gets++
	state, ok := c.items[key]
	return state, ok
}

func (c *syncStandardSessionCache) Put(key string, state *stdtls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.puts++
	if state == nil {
		delete(c.items, key)
		return
	}
	c.items[key] = state
}

func TestSyncTLS13ResumptionAndTicketConsumption(t *testing.T) {
	cases := []struct {
		name          string
		realityClient bool
	}{
		{"RealityClientStandardServer", true},
		{"StandardClientRealityServer", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert := syncNewCertificate(t, "localhost")
			var realityCache *syncRealitySessionCache
			var standardCache *syncStandardSessionCache
			if tc.realityClient {
				realityCache = &syncRealitySessionCache{items: make(map[string]*ClientSessionState)}
			} else {
				standardCache = &syncStandardSessionCache{items: make(map[string]*stdtls.ClientSessionState)}
			}
			var firstState, secondState ConnectionState
			var firstStdState, secondStdState stdtls.ConnectionState
			for i := 0; i < 2; i++ {
				pair := syncNewTransportPair(t, false)
				var client, server syncTLSConn
				if tc.realityClient {
					clientConfig := &Config{
						ServerName:         "localhost",
						InsecureSkipVerify: true,
						MinVersion:         VersionTLS13,
						MaxVersion:         VersionTLS13,
						ClientSessionCache: realityCache,
					}
					serverConfig := &stdtls.Config{
						Certificates:     []stdtls.Certificate{cert.std},
						MinVersion:       stdtls.VersionTLS13,
						MaxVersion:       stdtls.VersionTLS13,
						SessionTicketKey: [32]byte{0x47},
					}
					client = Client(pair.client, clientConfig)
					server = stdtls.Server(pair.server, serverConfig)
				} else {
					clientConfig := &stdtls.Config{
						Certificates:       []stdtls.Certificate{cert.std},
						ServerName:         "localhost",
						InsecureSkipVerify: true,
						MinVersion:         stdtls.VersionTLS13,
						MaxVersion:         stdtls.VersionTLS13,
						ClientSessionCache: standardCache,
					}
					serverConfig := &Config{
						Certificates:     []Certificate{cert.reality},
						MinVersion:       VersionTLS13,
						MaxVersion:       VersionTLS13,
						SessionTicketKey: [32]byte{0x47},
					}
					client = stdtls.Client(pair.client, clientConfig)
					server = serverConn(pair.server, serverConfig)
				}
				if err := syncRunTLSExchange(t, client, server, pair); err != nil {
					pair.close()
					t.Fatal(err)
				}
				if tc.realityClient {
					state := client.(*Conn).ConnectionState()
					if i == 0 {
						firstState = state
					} else {
						secondState = state
					}
				} else {
					state := client.(*stdtls.Conn).ConnectionState()
					if i == 0 {
						firstStdState = state
					} else {
						secondStdState = state
					}
				}
				pair.close()
				client.Close()
				server.Close()
			}
			if tc.realityClient {
				if firstState.DidResume {
					t.Fatal("first reality connection unexpectedly resumed")
				}
				if !secondState.DidResume {
					t.Fatal("second reality connection did not consume the TLS 1.3 ticket")
				}
				realityCache.mu.Lock()
				puts := realityCache.puts
				realityCache.mu.Unlock()
				if puts == 0 {
					t.Fatal("reality client session cache did not receive a ticket")
				}
			} else {
				if firstStdState.DidResume {
					t.Fatal("first standard connection unexpectedly resumed")
				}
				if !secondStdState.DidResume {
					t.Fatal("second standard connection did not consume the TLS 1.3 ticket")
				}
				standardCache.mu.Lock()
				puts := standardCache.puts
				standardCache.mu.Unlock()
				if puts == 0 {
					t.Fatal("standard client session cache did not receive a ticket")
				}
			}
		})
	}
}

type syncQUICPeer struct {
	name       string
	conn       *QUICConn
	complete   bool
	ticketSent bool
	gotStore   bool
}

func syncDriveQUIC(t *testing.T, client, server *syncQUICPeer) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), syncHandshakeTimeout)
	defer cancel()
	if err := client.conn.Start(ctx); err != nil {
		return fmt.Errorf("client start: %w", err)
	}
	if err := server.conn.Start(ctx); err != nil {
		return fmt.Errorf("server start: %w", err)
	}

	peers := [2]*syncQUICPeer{client, server}
	for step := 0; step < 10000; step++ {
		progress := false
		for _, src := range peers {
			e := src.conn.NextEvent()
			if e.Kind == QUICNoEvent {
				continue
			}
			progress = true
			switch e.Kind {
			case QUICWriteData:
				var dst *syncQUICPeer
				if src == client {
					dst = server
				} else {
					dst = client
				}
				if err := dst.conn.HandleData(e.Level, e.Data); err != nil {
					return fmt.Errorf("handle %s data: %w", src.name, err)
				}
			case QUICTransportParametersRequired:
				src.conn.SetTransportParameters([]byte{})
			case QUICHandshakeDone:
				src.complete = true
				if src == server && !src.ticketSent {
					if err := src.conn.SendSessionTicket(QUICSessionTicketOptions{}); err != nil {
						return fmt.Errorf("send QUIC session ticket: %w", err)
					}
					src.ticketSent = true
				}
			case QUICStoreSession:
				if src != client {
					return errors.New("server received QUICStoreSession")
				}
				if err := client.conn.StoreSession(e.SessionState); err != nil {
					return fmt.Errorf("store QUIC session: %w", err)
				}
				client.gotStore = true
			case QUICResumeSession:
				// No policy change is needed for the first handshake.
			case QUICSetReadSecret, QUICSetWriteSecret, QUICTransportParameters:
			case QUICRejectedEarlyData:
				return errors.New("unexpected QUIC early-data rejection")
			case QUICErrorEvent:
				return fmt.Errorf("%s QUIC error: %w", src.name, e.Err)
			default:
				return fmt.Errorf("unexpected QUIC event %v", e.Kind)
			}
		}
		if client.complete && server.complete && client.gotStore {
			return nil
		}
		if !progress {
			return errors.New("QUIC handshake made no progress")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	return errors.New("QUIC handshake exceeded event limit")
}

func TestSyncQUICEventsAndConnectionState(t *testing.T) {
	clientHelloInfoConn, peerConn := net.Pipe()
	defer clientHelloInfoConn.Close()
	defer peerConn.Close()
	serverCert := syncNewCertificate(t, "localhost")
	clientCert := syncNewCertificate(t, "client.localhost")
	var gotClientHelloInfoConn bool

	clientConfig := &Config{
		Certificates:       []Certificate{clientCert.reality},
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		MinVersion:         VersionTLS13,
		MaxVersion:         VersionTLS13,
		ClientSessionCache: NewLRUClientSessionCache(1),
	}
	serverConfig := &Config{
		Certificates: []Certificate{serverCert.reality},
		ClientAuth:   RequireAnyClientCert,
		MinVersion:   VersionTLS13,
		MaxVersion:   VersionTLS13,
		GetConfigForClient: func(info *ClientHelloInfo) (*Config, error) {
			if info.Conn != clientHelloInfoConn {
				return nil, fmt.Errorf("ClientHelloInfo.Conn = %v, want configured connection", info.Conn)
			}
			gotClientHelloInfoConn = true
			return nil, nil
		},
	}
	client := &syncQUICPeer{name: "client", conn: QUICClient(&QUICConfig{
		TLSConfig:           clientConfig,
		EnableSessionEvents: true,
	})}
	server := &syncQUICPeer{name: "server", conn: QUICServer(&QUICConfig{
		TLSConfig:           serverConfig,
		ClientHelloInfoConn: clientHelloInfoConn,
	})}
	client.conn.SetTransportParameters([]byte{1, 2, 3})
	server.conn.SetTransportParameters([]byte{4, 5, 6})
	defer client.conn.Close()
	defer server.conn.Close()

	if err := syncDriveQUIC(t, client, server); err != nil {
		t.Fatal(err)
	}
	if !gotClientHelloInfoConn {
		t.Fatal("server GetConfigForClient callback was not called")
	}
	if !client.gotStore {
		t.Fatal("client did not receive a QUICStoreSession event")
	}
	clientState := client.conn.ConnectionState()
	serverState := server.conn.ConnectionState()
	if !bytes.Equal(clientState.LocalCertificate[0], clientCert.der) {
		t.Fatalf("client LocalCertificate = %x, want client certificate", clientState.LocalCertificate)
	}
	if !bytes.Equal(serverState.LocalCertificate[0], serverCert.der) {
		t.Fatalf("server LocalCertificate = %x, want server certificate", serverState.LocalCertificate)
	}
	if clientState.Version != VersionTLS13 || serverState.Version != VersionTLS13 {
		t.Fatalf("QUIC versions = %x/%x, want TLS 1.3", clientState.Version, serverState.Version)
	}
}
