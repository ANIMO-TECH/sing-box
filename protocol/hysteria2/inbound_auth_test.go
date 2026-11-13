package hysteria2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	upstream "github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const testToken = "test-proxy-token"

type authTestRouter struct {
	adapter.Router
	users chan string
}

func (r *authTestRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.users <- metadata.User
	go func() { defer conn.Close(); io.Copy(conn, conn) }()
}

func (r *authTestRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.users <- metadata.User
	go func() {
		defer conn.Close()
		packet := buf.NewPacket()
		destination, err := conn.ReadPacket(packet)
		if err != nil {
			packet.Release()
			return
		}
		conn.WritePacket(packet, destination)
	}()
}

func testCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

func startAuthTestInbound(t *testing.T, external *option.TrojanHTTPAuthOptions) (*authTestRouter, func(string) *upstream.Client) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	logger := log.NewNOPFactory().NewLogger("test")
	cert, key := testCertificate(t)
	router := &authTestRouter{users: make(chan string, 16)}
	options := option.Hysteria2InboundOptions{
		ListenOptions: option.ListenOptions{Listen: common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1")))},
		HTTPAuth:      external,
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
			Enabled: true, Certificate: []string{cert}, Key: []string{key},
		}},
	}
	if external == nil {
		options.Users = []option.Hysteria2User{{Name: "static-user", Password: testToken}}
	}
	inbound, err := NewInbound(ctx, router, logger, "test", options)
	if err != nil {
		t.Fatal(err)
	}
	scope := adapter.NewScope(ctx, logger)
	t.Cleanup(func() { scope.Close() })
	if err = inbound.Start(adapter.StartStateStart, scope); err != nil {
		t.Fatal(err)
	}
	address := M.SocksaddrFromNet(inbound.(*Inbound).listener.UDPConn().LocalAddr()).Unwrap()
	return router, func(password string) *upstream.Client {
		config, err := tls.NewClient(ctx, logger, "localhost", option.OutboundTLSOptions{Enabled: true, ServerName: "localhost", Certificate: []string{cert}})
		if err != nil {
			t.Fatal(err)
		}
		client, err := upstream.NewClient(upstream.ClientOptions{
			Context: ctx, Dialer: N.SystemDialer, Logger: logger, ServerAddress: address,
			Password: password, TLSConfig: config,
		})
		if err != nil {
			t.Fatal(err)
		}
		client.SetKeepIdleConnections(true)
		t.Cleanup(func() { client.CloseWithError(net.ErrClosed) })
		return client
	}
}

func echoTCP(t *testing.T, client *upstream.Client, success bool) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := client.DialConn(ctx, M.ParseSocksaddr("example.com:443"))
	if err == nil {
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Write([]byte("hello"))
		if err == nil {
			var reply [5]byte
			_, err = io.ReadFull(conn, reply[:])
			if err == nil && string(reply[:]) != "hello" {
				t.Fatal("payload changed")
			}
		}
	}
	if (err == nil) != success {
		t.Fatalf("unexpected connection outcome: %v", err)
	}
	if conn != nil {
		t.Cleanup(func() { conn.Close() })
	}
	return conn
}

func expectUser(t *testing.T, router *authTestRouter, user string) {
	t.Helper()
	select {
	case actual := <-router.users:
		if actual != user {
			t.Fatalf("user = %q, want %q", actual, user)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("connection was not routed")
	}
}

func TestExternalAuthenticationInteroperabilityAndRevocation(t *testing.T) {
	var valid atomic.Bool
	valid.Store(true)
	var calls atomic.Int32
	digest := sha256.Sum224([]byte(testToken))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var payload struct {
			Digest string `json:"digest"`
		}
		if r.Method != http.MethodPost || r.Header.Get("X-Gateway-Service-Token") != "test-service" || json.NewDecoder(r.Body).Decode(&payload) != nil {
			t.Error("authentication request contract changed")
		}
		accepted := valid.Load() && payload.Digest == hex.EncodeToString(digest[:])
		json.NewEncoder(w).Encode(map[string]any{"code": 0, "result": map[string]any{"valid": accepted, "email": "user@example.com"}})
	}))
	defer server.Close()
	router, newClient := startAuthTestInbound(t, &option.TrojanHTTPAuthOptions{URL: server.URL, ServiceToken: "test-service"})
	client := newClient(testToken)
	// Leave this stream open to prove the revoked attempt reuses authenticated QUIC.
	first := echoTCP(t, client, true)
	expectUser(t, router, "user@example.com")
	if calls.Load() != 2 {
		t.Fatalf("expected handshake and stream validation, got %d", calls.Load())
	}
	valid.Store(false)
	echoTCP(t, client, false)
	if calls.Load() != 3 {
		t.Fatalf("new stream did not revalidate on existing QUIC: %d", calls.Load())
	}
	select {
	case <-router.users:
		t.Fatal("revoked token was routed")
	default:
	}
	// Existing streams retain the documented Trojan semantics.
	if _, err := first.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	var reply [5]byte
	if _, err := io.ReadFull(first, reply[:]); err != nil {
		t.Fatal(err)
	}
	valid.Store(true)
	echoTCP(t, newClient("invalid-token"), false)
}

func TestExternalAuthenticationUDPAndUnavailableBackend(t *testing.T) {
	var available atomic.Bool
	available.Store(true)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !available.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, `{"code":0,"result":{"valid":true,"email":"user@example.com"}}`)
	}))
	defer server.Close()
	router, newClient := startAuthTestInbound(t, &option.TrojanHTTPAuthOptions{URL: server.URL, ServiceToken: "test-service"})
	client := newClient(testToken)
	packet, err := client.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	if err = packet.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	destination := M.ParseSocksaddr("example.com:53")
	if _, err = packet.WriteTo([]byte("hello"), destination); err != nil {
		t.Fatal(err)
	}
	var reply [16]byte
	if n, _, err := packet.ReadFrom(reply[:]); err != nil || string(reply[:n]) != "hello" {
		t.Fatalf("UDP echo failed: %v", err)
	}
	expectUser(t, router, "user@example.com")
	available.Store(false)
	before := calls.Load()
	packet2, err := client.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer packet2.Close()
	if err = packet2.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	packet2.WriteTo([]byte("hello"), destination)
	if _, _, err := packet2.ReadFrom(reply[:]); err == nil {
		t.Fatal("unavailable backend allowed new UDP session")
	}
	if calls.Load() != before+1 {
		t.Fatal("new UDP session did not query backend")
	}
	select {
	case <-router.users:
		t.Fatal("denied UDP session was routed")
	default:
	}
}

func TestStaticAuthenticationCompatibilityAndExclusiveConfiguration(t *testing.T) {
	router, newClient := startAuthTestInbound(t, nil)
	echoTCP(t, newClient(testToken), true)
	expectUser(t, router, "static-user")
	echoTCP(t, newClient("invalid"), false)
	_, err := NewInbound(context.Background(), nil, nil, "test", option.Hysteria2InboundOptions{
		Users: []option.Hysteria2User{{Password: "static"}}, HTTPAuth: &option.TrojanHTTPAuthOptions{},
	})
	if err == nil {
		t.Fatal("static and external authentication must be mutually exclusive")
	}
}
