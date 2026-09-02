package reality

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }

type testConn struct {
	readErr  error
	writeErr error
	closed   chan struct{}
	once     sync.Once
}

func newTestConn(readErr error) *testConn {
	return &testConn{
		readErr: readErr,
		closed:  make(chan struct{}),
	}
}

func (c *testConn) Read([]byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	return 0, io.EOF
}

func (c *testConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}

func (c *testConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *testConn) LocalAddr() net.Addr              { return testAddr("local") }
func (c *testConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *testConn) SetDeadline(time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(time.Time) error { return nil }

type testCloseWriteConn struct {
	net.Conn
	calls atomic.Int32
}

func (c *testCloseWriteConn) CloseWrite() error {
	c.calls.Add(1)
	return nil
}

func TestDialContextUsesConfiguredDialer(t *testing.T) {
	wantErr := errors.New("dial failed")
	ctx := context.WithValue(context.Background(), struct{}{}, "value")
	var gotNetwork, gotAddress string
	var gotContext context.Context
	config := &Config{
		DialContext: func(gotCtx context.Context, network, address string) (net.Conn, error) {
			gotContext = gotCtx
			gotNetwork = network
			gotAddress = address
			return nil, wantErr
		},
	}

	_, err := dialContext(ctx, config, "test", "destination")
	if !errors.Is(err, wantErr) {
		t.Fatalf("dialContext error = %v, want %v", err, wantErr)
	}
	if gotContext != ctx {
		t.Fatal("dialContext did not pass the caller's context")
	}
	if gotNetwork != "test" || gotAddress != "destination" {
		t.Fatalf("dialContext arguments = (%q, %q), want (%q, %q)", gotNetwork, gotAddress, "test", "destination")
	}
}

func TestDialContextFallsBackToNetDialer(t *testing.T) {
	_, err := dialContext(context.Background(), &Config{}, "invalid-network", "destination")
	if err == nil {
		t.Fatal("dialContext with a nil Config.DialContext returned no error")
	}
}

func TestServerUsesDefaultDialerWhenConfigDialContextIsNil(t *testing.T) {
	incoming := newTestConn(io.EOF)
	_, err := Server(context.Background(), incoming, &Config{
		Type: "invalid-network",
		Dest: "destination",
	})
	if err == nil {
		t.Fatal("Server returned nil error for an invalid target network")
	}
}

func TestCloseWriteIsOptional(t *testing.T) {
	conn := &testCloseWriteConn{Conn: newTestConn(nil)}
	closeWrite(conn)
	if got := conn.calls.Load(); got != 1 {
		t.Fatalf("CloseWrite calls = %d, want 1", got)
	}

	closeWrite(newTestConn(nil))
}

func TestServerAcceptsConnWithoutCloseWrite(t *testing.T) {
	incoming := newTestConn(io.EOF)
	target := newTestConn(io.EOF)
	config := &Config{
		Type: "test",
		Dest: "target",
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return target, nil
		},
	}

	result := make(chan error, 1)
	go func() {
		_, err := Server(context.Background(), incoming, config)
		result <- err
	}()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("Server returned nil error for an incomplete connection")
		}
	case <-time.After(5 * time.Second):
		incoming.Close()
		t.Fatal("Server did not return")
	}

	select {
	case <-target.closed:
	case <-time.After(time.Second):
		t.Fatal("Server did not close the target connection")
	}
}

type probeDialCall struct {
	ctx     context.Context
	network string
	address string
}

func TestDetectPostHandshakeRecordsLensUsesDialerAndClosesConnections(t *testing.T) {
	sni := "probe.example"
	dest := "probe-" + t.Name()
	config := &Config{
		Type:        "test",
		Dest:        dest,
		ServerNames: map[string]bool{sni: true},
	}
	calls := make(chan probeDialCall, 8)
	connections := make(chan *testConn, 8)
	config.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn := newTestConn(io.EOF)
		calls <- probeDialCall{ctx: ctx, network: network, address: address}
		connections <- conn
		return conn, nil
	}
	t.Cleanup(func() {
		for alpn := range 3 {
			key := dest + " " + sni + " " + strconv.Itoa(alpn)
			GlobalPostHandshakeRecordsLens.Delete(key)
			GlobalMaxCSSMsgCount.Delete(key)
		}
	})

	DetectPostHandshakeRecordsLens(config)

	gotConnections := make([]*testConn, 6)
	for i := range gotConnections {
		select {
		case call := <-calls:
			if call.ctx == nil {
				t.Fatal("probe dialer received a nil context")
			}
			if call.network != config.Type || call.address != config.Dest {
				t.Fatalf("probe dialer arguments = (%q, %q), want (%q, %q)", call.network, call.address, config.Type, config.Dest)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("received %d probe dial calls, want 6", i)
		}
		select {
		case gotConnections[i] = <-connections:
		case <-time.After(5 * time.Second):
			t.Fatalf("received %d probe connections, want 6", i)
		}
	}

	for i, conn := range gotConnections {
		select {
		case <-conn.closed:
		case <-time.After(5 * time.Second):
			t.Fatalf("probe connection %d was not closed", i)
		}
	}
}
