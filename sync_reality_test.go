package reality

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type syncRealityRecordingConn struct {
	net.Conn
	read bytes.Buffer
}

func (c *syncRealityRecordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Write(p[:n])
	return n, err
}

func syncRealityRecord(typ recordType, payload []byte) []byte {
	record := []byte{byte(typ), 3, 3, byte(len(payload) >> 8), byte(len(payload))}
	return append(record, payload...)
}

func syncRealityReadRecord(r io.Reader) ([]byte, error) {
	header := make([]byte, recordHeaderLen)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	record := make([]byte, recordHeaderLen+int(binary.BigEndian.Uint16(header[3:])))
	copy(record, header)
	_, err := io.ReadFull(r, record[recordHeaderLen:])
	return record, err
}

// The target's encrypted flight is deliberately opaque. REALITY must preserve
// its record lengths while generating an independently verifiable TLS flight.
func TestSyncRealityHandshake(t *testing.T) {
	for _, group := range curvePreferenceOrder() {
		for _, coalesced := range []bool{false, true} {
			for _, mldsa := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/coalesced=%t/mldsa=%t", group, coalesced, mldsa), func(t *testing.T) {
					testSyncRealityHandshake(t, group, coalesced, mldsa)
				})
			}
		}
	}
}

func testSyncRealityHandshake(t *testing.T, group CurveID, coalesced, useMLDSA bool) {
	t.Helper()
	clientWire, serverWire := net.Pipe()
	targetWire, targetPeer := net.Pipe()
	for _, conn := range []net.Conn{clientWire, serverWire, targetWire, targetPeer} {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		t.Cleanup(func() { conn.Close() })
	}
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shortID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	config := &Config{
		Type: "test", Dest: t.Name(),
		ServerNames: map[string]bool{"target.example": true},
		PrivateKey:  privateKey.Bytes(), ShortIds: map[[8]byte]bool{shortID: true},
		MaxTimeDiff: time.Minute,
		DialContext: func(context.Context, string, string) (net.Conn, error) { return targetWire, nil },
	}
	var mldsaPublic *mldsa65.PublicKey
	if useMLDSA {
		pub, priv, err := mldsa65.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		mldsaPublic = pub
		config.Mldsa65Key, err = priv.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
	}
	lengths := []int{128, 4096, 256, 128, 256}
	if coalesced {
		lengths = []int{6144}
	}
	cacheKey := config.Dest + " target.example 0"
	postHandshakeLengths := []int{128, 256}
	GlobalPostHandshakeRecordsLens.Store(cacheKey, postHandshakeLengths)
	t.Cleanup(func() { GlobalPostHandshakeRecordsLens.Delete(cacheKey) })

	targetHello := make(chan []byte, 1)
	targetResult := make(chan error, 1)
	go func() {
		record, err := syncRealityReadRecord(targetPeer)
		if err != nil {
			targetResult <- err
			return
		}
		ch := new(clientHelloMsg)
		if !ch.unmarshal(record[recordHeaderLen:]) {
			targetResult <- fmt.Errorf("target received invalid ClientHello")
			return
		}
		shareLen, _ := expectedServerKeyShareLen(group)
		hello := &serverHelloMsg{
			vers: VersionTLS12, supportedVersion: VersionTLS13,
			random: bytes.Repeat([]byte{42}, 32), sessionId: ch.sessionId,
			cipherSuite: TLS_AES_128_GCM_SHA256,
			serverShare: keyShare{group: group, data: bytes.Repeat([]byte{7}, shareLen)},
		}
		raw, err := hello.marshal()
		if err != nil {
			targetResult <- err
			return
		}
		// Include an unknown extension that marshaling the parsed struct would
		// discard. Mirroring must retain the exact target serialization.
		extLenOffset := 42 + len(ch.sessionId)
		raw = append(raw, 0xfa, 0xfa, 0, 3, 1, 2, 3)
		binary.BigEndian.PutUint16(raw[extLenOffset:], uint16(len(raw)-extLenOffset-2))
		bodyLen := len(raw) - 4
		raw[1], raw[2], raw[3] = byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen)
		targetHello <- bytes.Clone(raw)
		flight := syncRealityRecord(recordTypeHandshake, raw)
		flight = append(flight, syncRealityRecord(recordTypeChangeCipherSpec, []byte{1})...)
		for _, length := range lengths {
			flight = append(flight, syncRealityRecord(recordTypeApplicationData, make([]byte, length-recordHeaderLen))...)
		}
		if _, err := targetPeer.Write(flight); err != nil {
			targetResult <- err
			return
		}
		_, err = io.Copy(io.Discard, targetPeer)
		targetResult <- err
	}()

	serverResult := make(chan error, 1)
	go func() {
		server, err := Server(context.Background(), serverWire, config)
		if err == nil {
			if !server.ConnectionState().HandshakeComplete || len(server.ConnectionState().LocalCertificate) != 1 {
				err = fmt.Errorf("REALITY server connection state is incomplete")
			} else {
				// This also ensures Finished was consumed exactly once and the
				// application traffic keys are installed on both sides.
				payload := make([]byte, 4)
				if _, err = io.ReadFull(server, payload); err == nil {
					_, err = server.Write(payload)
				}
			}
		}
		serverResult <- err
	}()

	recordedClientWire := &syncRealityRecordingConn{Conn: clientWire}
	client := Client(recordedClientWire, &Config{
		ServerName: "target.example", InsecureSkipVerify: true,
		MinVersion: VersionTLS13, MaxVersion: VersionTLS13, CurvePreferences: []CurveID{group},
	})
	var authKey, mirroredHello, sentHello []byte
	client.config.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("synthetic certificate is not Ed25519")
		}
		h := hmac.New(sha512.New, authKey)
		h.Write(pub)
		if !hmac.Equal(h.Sum(nil), cert.Signature) {
			return fmt.Errorf("synthetic certificate is not bound to authentication key")
		}
		if useMLDSA {
			h.Write(sentHello)
			h.Write(mirroredHello)
			if len(cert.Extensions) != 1 || !mldsa65.Verify(mldsaPublic, h.Sum(nil), nil, cert.Extensions[0].Value) {
				return fmt.Errorf("ML-DSA extension is not bound to both hellos")
			}
		}
		return nil
	}
	client.handshakeFn = func(ctx context.Context) error {
		hello, keys, _, err := client.makeClientHello()
		if err != nil {
			return err
		}
		// Authentication remains X25519 based even when the target selects
		// a different TLS key exchange.
		authPrivate := keys.ecdhe
		if authPrivate == nil || authPrivate.Curve() != ecdh.X25519() {
			authPrivate, err = ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			hello.keyShares = append(hello.keyShares, keyShare{group: X25519, data: authPrivate.PublicKey().Bytes()})
			hello.supportedCurves = append(hello.supportedCurves, X25519)
		}
		secret, err := authPrivate.ECDH(privateKey.PublicKey())
		if err != nil {
			return err
		}
		authKey, err = hkdf.Key(sha256.New, secret, hello.random[:20], "REALITY", 32)
		if err != nil {
			return err
		}
		hello.sessionId = make([]byte, 32)
		hello.pskModes = []byte{pskModeDHE}
		aad, err := hello.marshal()
		if err != nil {
			return err
		}
		plain := make([]byte, 16)
		plain[0] = 1
		binary.BigEndian.PutUint32(plain[4:], uint32(time.Now().Unix()))
		copy(plain[8:], shortID[:])
		block, err := aes.NewCipher(authKey)
		if err != nil {
			return err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		hello.sessionId = aead.Seal(nil, hello.random[20:], plain, aad)
		sentHello, err = hello.marshal()
		if err != nil {
			return err
		}
		if _, err := client.writeHandshakeRecord(hello, nil); err != nil {
			return err
		}
		msg, err := client.readHandshake(nil)
		if err != nil {
			return err
		}
		serverHello, ok := msg.(*serverHelloMsg)
		if !ok {
			return fmt.Errorf("received %T, want ServerHello", msg)
		}
		mirroredHello = bytes.Clone(serverHello.original)
		if err := client.pickTLSVersion(serverHello); err != nil {
			return err
		}
		hs := &clientHandshakeStateTLS13{c: client, ctx: ctx, hello: hello, serverHello: serverHello, keyShareKeys: keys}
		return hs.handshake()
	}
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	writeResult := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("ping"))
		writeResult <- err
	}()
	payload := make([]byte, 4)
	if _, err := io.ReadFull(client, payload); err != nil {
		t.Fatal(err)
	}
	if err := <-writeResult; err != nil {
		t.Fatal(err)
	}
	if string(payload) != "ping" {
		t.Fatalf("application data = %q", payload)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("server: %v", err)
	}
	if err := <-targetResult; err != nil {
		t.Fatalf("target: %v", err)
	}
	original, mirrored := new(serverHelloMsg), new(serverHelloMsg)
	if !original.unmarshal(<-targetHello) || !mirrored.unmarshal(mirroredHello) {
		t.Fatal("could not parse captured ServerHello")
	}
	if bytes.Equal(original.serverShare.data, mirrored.serverShare.data) {
		t.Fatal("target key share was not replaced")
	}
	wantLengths := append([]int{recordHeaderLen + len(original.original), 6}, lengths...)
	wantLengths = append(wantLengths, postHandshakeLengths...)
	for i, want := range wantLengths {
		record, err := syncRealityReadRecord(&recordedClientWire.read)
		if err != nil {
			t.Fatalf("captured record %d: %v", i, err)
		}
		if len(record) != want {
			t.Fatalf("record %d length = %d, want target length %d", i, len(record), want)
		}
	}
	clear(original.serverShare.data)
	clear(mirrored.serverShare.data)
	if !bytes.Equal(original.original, mirrored.original) {
		t.Fatal("target ServerHello changed outside its key share")
	}
}

func TestSyncKeyShareValidation(t *testing.T) {
	for _, group := range curvePreferenceOrder() {
		t.Run(group.String(), func(t *testing.T) {
			ke, err := keyExchangeForCurveID(group)
			if err != nil {
				t.Fatal(err)
			}
			keys, shares, err := ke.keyShares(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			var clientShare []byte
			for _, share := range shares {
				if share.group == group {
					clientShare = share.data
				}
			}
			if len(clientShare) == 0 {
				t.Fatal("missing client key share")
			}
			for _, malformed := range [][]byte{nil, clientShare[:len(clientShare)-1], append(bytes.Clone(clientShare), 0)} {
				if _, _, err := ke.serverSharedSecret(rand.Reader, malformed); err == nil {
					t.Fatalf("accepted client share of length %d", len(malformed))
				}
			}
			_, serverShare, err := ke.serverSharedSecret(rand.Reader, clientShare)
			if err != nil {
				t.Fatal(err)
			}
			wantLen, ok := expectedServerKeyShareLen(group)
			if !ok || len(serverShare.data) != wantLen {
				t.Fatalf("server share length = %d, want %d", len(serverShare.data), wantLen)
			}
			for _, malformed := range [][]byte{nil, serverShare.data[:wantLen-1], append(bytes.Clone(serverShare.data), 0)} {
				if _, err := ke.clientSharedSecret(keys, malformed); err == nil {
					t.Fatalf("accepted server share of length %d", len(malformed))
				}
			}
		})
	}
	if _, ok := expectedServerKeyShareLen(CurveID(0xffff)); ok {
		t.Fatal("accepted unknown target group")
	}
}

func TestSyncRealityPaddingBounds(t *testing.T) {
	for _, length := range []int{25, 26, 8192} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			suite := cipherSuiteTLS13ByID(TLS_AES_128_GCM_SHA256)
			c := &Conn{vers: VersionTLS13}
			c.out.version = VersionTLS13
			c.setWriteTrafficSecret(suite, QUICEncryptionLevelHandshake, make([]byte, suite.hash.Size()))
			c.out.handshakeLen[1] = 6
			c.out.handshakeLen[5] = length
			record, err := c.out.encrypt([]byte{byte(recordTypeHandshake), 3, 3, 0, 0}, []byte{typeFinished, 0, 0, 0}, rand.Reader)
			if length < 26 {
				if err == nil {
					t.Fatal("accepted target record too short for the handshake payload")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(record) != length || int(binary.BigEndian.Uint16(record[3:])) != length-recordHeaderLen {
				t.Fatalf("padded record length = %d, want %d", len(record), length)
			}
		})
	}
}

func TestSyncRealityFallback(t *testing.T) {
	for _, rejection := range []string{"authentication", "timestamp", "short-id", "server-name", "client-version"} {
		t.Run(rejection, func(t *testing.T) {
			clientWire, serverWire := net.Pipe()
			targetWire, targetPeer := net.Pipe()
			for _, conn := range []net.Conn{clientWire, serverWire, targetWire, targetPeer} {
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				t.Cleanup(func() { conn.Close() })
			}
			privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			client := Client(clientWire, &Config{ServerName: "target.example", MinVersion: VersionTLS13, CurvePreferences: []CurveID{X25519}})
			hello, keys, _, err := client.makeClientHello()
			if err != nil {
				t.Fatal(err)
			}
			hello.sessionId = make([]byte, 32)
			aad, err := hello.marshal()
			if err != nil {
				t.Fatal(err)
			}
			secret, err := keys.ecdhe.ECDH(privateKey.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			authKey, err := hkdf.Key(sha256.New, secret, hello.random[:20], "REALITY", 32)
			if err != nil {
				t.Fatal(err)
			}
			plain := make([]byte, 16)
			plain[0] = 1
			binary.BigEndian.PutUint32(plain[4:], uint32(time.Now().Unix()))
			config := &Config{
				Type: "test", Dest: "fallback", PrivateKey: privateKey.Bytes(),
				ServerNames: map[string]bool{"target.example": true},
				ShortIds:    map[[8]byte]bool{{}: true}, MaxTimeDiff: time.Minute,
				DialContext:           func(context.Context, string, string) (net.Conn, error) { return targetWire, nil },
				LimitFallbackUpload:   LimitFallback{BytesPerSec: 1 << 20},
				LimitFallbackDownload: LimitFallback{BytesPerSec: 1 << 20},
			}
			switch rejection {
			case "timestamp":
				binary.BigEndian.PutUint32(plain[4:], uint32(time.Now().Add(-time.Hour).Unix()))
			case "short-id":
				plain[8] = 1
			case "server-name":
				config.ServerNames = map[string]bool{"other.example": true}
			case "client-version":
				config.MinClientVer = []byte{2, 0, 0}
			}
			block, err := aes.NewCipher(authKey)
			if err != nil {
				t.Fatal(err)
			}
			aead, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatal(err)
			}
			hello.sessionId = aead.Seal(nil, hello.random[20:], plain, aad)
			if rejection == "authentication" {
				hello.sessionId[0] ^= 1
			}
			raw, err := hello.marshal()
			if err != nil {
				t.Fatal(err)
			}
			serverResult := make(chan error, 1)
			go func() {
				_, err := Server(context.Background(), serverWire, config)
				serverResult <- err
			}()
			response := []byte("target fallback response")
			targetResult := make(chan error, 1)
			go func() {
				record, err := syncRealityReadRecord(targetPeer)
				if err == nil && !bytes.Equal(record[recordHeaderLen:], raw) {
					err = fmt.Errorf("fallback changed ClientHello bytes")
				}
				if err == nil {
					_, err = targetPeer.Write(response)
				}
				targetResult <- err
				targetPeer.Close()
			}()
			if _, err := clientWire.Write(syncRealityRecord(recordTypeHandshake, raw)); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(response))
			if _, err := io.ReadFull(clientWire, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, response) {
				t.Fatalf("fallback response = %q", got)
			}
			clientWire.Close()
			if err := <-targetResult; err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-serverResult:
				if err == nil {
					t.Fatal("accepted rejected authentication")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("fallback did not close")
			}
		})
	}
}

func TestSyncPostHandshakeDefaultRecordLimit(t *testing.T) {
	for _, limit := range []int{0, -1, 2} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			c := &Conn{conn: newTestConn(nil), config: &Config{SessionTicketsDisabled: true}, isClient: true, vers: VersionTLS13, MaxUselessRecords: limit}
			msg := &newSessionTicketMsgTLS13{label: []byte{1}, lifetime: 1}
			raw, err := msg.marshal()
			if err != nil {
				t.Fatal(err)
			}
			wantLimit := limit
			if wantLimit <= 0 {
				wantLimit = maxUselessRecords
			}
			for i := 0; i < wantLimit; i++ {
				c.hand.Write(raw)
				if err := c.handlePostHandshakeMessage(); err != nil {
					t.Fatalf("message %d of %d: %v", i+1, wantLimit, err)
				}
			}
			c.hand.Write(raw)
			if err := c.handlePostHandshakeMessage(); err == nil {
				t.Fatal("accepted message beyond configured non-advancing record limit")
			}
		})
	}
}
