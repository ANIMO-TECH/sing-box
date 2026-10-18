package trojan

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type identityHandler struct {
	user        string
	destination M.Socksaddr
	called      bool
}

func (h *identityHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.user, _ = auth.UserFromContext[string](ctx)
	h.destination = destination
	h.called = true
}
func (h *identityHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.user, _ = auth.UserFromContext[string](ctx)
	h.called = true
}

type fragmentedConn struct{ net.Conn }

func (c fragmentedConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := c.Conn.Write(p[:1])
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func TestAuthenticationPreservesIdentityThroughFragmentedHandshake(t *testing.T) {
	for _, external := range []bool{false, true} {
		handler := &identityHandler{}
		service := NewService[string](handler, nil, nil)
		if err := service.UpdateUsers([]string{"static-user"}, []string{"test-token"}); err != nil {
			t.Fatal(err)
		}
		expected := "static-user"
		if external {
			expected = "admin@example.com"
			service.SetAuthenticator(func(ctx context.Context, digest string, source M.Socksaddr) (string, error) {
				key := Key("test-token")
				if digest != string(key[:]) {
					t.Error("wire digest mismatch")
				}
				return expected, nil
			})
		}
		server, client := net.Pipe()
		server.SetDeadline(time.Now().Add(time.Second))
		client.SetDeadline(time.Now().Add(time.Second))
		destination := M.ParseSocksaddr("example.com:443")
		written := make(chan error, 1)
		go func() { written <- ClientHandshake(fragmentedConn{client}, Key("test-token"), destination, nil) }()
		err := service.NewConnection(context.Background(), server, M.ParseSocksaddr("127.0.0.1:1234"), nil)
		server.Close()
		client.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err = <-written; err != nil {
			t.Fatal(err)
		}
		if !handler.called || handler.user != expected || handler.destination != destination {
			t.Fatal("lost authenticated user or destination")
		}
	}
}

func TestExternalFailureCannotUseStaticPasswordOrFallback(t *testing.T) {
	handler := &identityHandler{}
	fallback := &identityHandler{}
	service := NewService[string](handler, fallback, nil)
	service.UpdateUsers([]string{"static-user"}, []string{"test-token"})
	service.SetAuthenticator(func(context.Context, string, M.Socksaddr) (string, error) { return "", errors.New("denied") })
	server, client := net.Pipe()
	server.SetDeadline(time.Now().Add(time.Second))
	client.SetDeadline(time.Now().Add(time.Second))
	defer server.Close()
	defer client.Close()
	go func() { key := Key("test-token"); client.Write(key[:]) }()
	if service.NewConnection(context.Background(), server, M.Socksaddr{}, nil) == nil {
		t.Fatal("external denial accepted")
	}
	if handler.called || fallback.called {
		t.Fatal("denied credential fell back")
	}
}
