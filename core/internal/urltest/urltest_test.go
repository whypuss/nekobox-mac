// SPDX-License-Identifier: GPL-3.0-or-later
package urltest_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"nekobox-mac/internal/mihomobridge"
	"nekobox-mac/internal/urltest"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	SJSON "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
)

type lazyHandshakeConn struct {
	net.Conn
	delay time.Duration
	once  sync.Once
}

func (c *lazyHandshakeConn) Write(p []byte) (int, error) {
	c.once.Do(func() {
		time.Sleep(c.delay)
	})
	return c.Conn.Write(p)
}

type lazyHandshakeDialer struct {
	delay time.Duration
}

func (d *lazyHandshakeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var nd net.Dialer
	conn, err := nd.DialContext(ctx, network, destination.String())
	if err != nil {
		return nil, err
	}
	return &lazyHandshakeConn{Conn: conn, delay: d.delay}, nil
}

func (d *lazyHandshakeDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrPermission
}

func TestKeepAliveHTTPAndRedirect(t *testing.T) {
	var hits atomic.Int32
	var finalHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/final" {
			finalHits.Add(1)
		}
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "/final")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	latency, err := urltest.Test(nil, srv.URL+"/generate_204", 3000, nil)
	if err != nil {
		t.Fatalf("HTTP 204 test failed: %v", err)
	}
	if latency < 1 {
		t.Fatalf("expected positive latency >= 1ms, got %d", latency)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("expected warm+reused 2 HTTP requests, got %d", got)
	}

	latency, err = urltest.Test(nil, srv.URL+"/redirect", 3000, nil)
	if err != nil {
		t.Fatalf("HTTP 302 test failed: %v", err)
	}
	if latency < 1 {
		t.Fatalf("expected positive latency >= 1ms, got %d", latency)
	}
	if got := finalHits.Load(); got != 0 {
		t.Fatalf("expected redirect not to be followed, got %d hits to /final", got)
	}
}

func TestPureRTTExcludesLazyProxyHandshake(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	dialer := &lazyHandshakeDialer{delay: 250 * time.Millisecond}
	latency, err := urltest.Test(dialer, srv.URL+"/generate_204", 3000, nil)
	if err != nil {
		t.Fatalf("HTTP pure RTT test failed: %v", err)
	}
	if latency >= 150 {
		t.Fatalf("expected pure 1-RTT latency excluding 250ms cold handshake, got %dms", latency)
	}
}

func TestFallbackWhenServerClosesKeepAlive(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	latency, err := urltest.Test(nil, srv.URL+"/generate_204", 3000, nil)
	if err != nil {
		t.Fatalf("HTTP Connection:close fallback failed: %v", err)
	}
	if latency < 1 {
		t.Fatalf("expected positive latency >= 1ms, got %d", latency)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("expected 1 request when server closes keep-alive, got %d", got)
	}
}

func TestSingleRequestHTTPSWithRootCA(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	dialer := &lazyHandshakeDialer{delay: 250 * time.Millisecond}
	latency, err := urltest.Test(dialer, srv.URL+"/generate_204", 3000, roots)
	if err != nil {
		t.Fatalf("HTTPS test failed: %v", err)
	}
	if latency < 1 || latency >= 150 {
		t.Fatalf("expected pure HTTPS 1-RTT excluding 250ms cold handshake, got %dms", latency)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("expected single HTTPS request, got %d", got)
	}
}

func TestTimeoutError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	_, err := urltest.Test(nil, srv.URL, 150, nil)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestPickOutboundAndProxyURLTest(t *testing.T) {
	mihomobridge.Install(nil)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	// Start a real local sing-box SOCKS5 server.
	socksPort := freeTCPPort(t)
	serverCtx := box.Context(context.Background(), include.InboundRegistry(), include.OutboundRegistry(),
		include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry(), include.CertificateProviderRegistry())
	serverRaw, _ := json.Marshal(map[string]any{
		"log": map[string]any{"level": "error"},
		"inbounds": []any{map[string]any{
			"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": socksPort,
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	})
	serverOpts, err := SJSON.UnmarshalExtendedContext[option.Options](serverCtx, serverRaw)
	if err != nil {
		t.Fatalf("decode server options: %v", err)
	}
	serverBox, err := box.New(box.Options{Context: serverCtx, Options: serverOpts})
	if err != nil {
		t.Fatalf("create server box: %v", err)
	}
	if err := serverBox.Start(); err != nil {
		t.Fatalf("start server box: %v", err)
	}
	defer serverBox.Close()

	// Put direct FIRST and "proxy" SECOND so PickOutbound verifies fallback to "proxy".
	outbounds := include.OutboundRegistry()
	mihomobridge.Register(outbounds)
	clientCtx := box.Context(context.Background(), include.InboundRegistry(), outbounds,
		include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry(), include.CertificateProviderRegistry())
	clientRaw, _ := json.Marshal(map[string]any{
		"log": map[string]any{"level": "error"},
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": "direct"},
			map[string]any{
				"type": "mihomo",
				"tag":  "proxy",
				"proxy": map[string]any{
					"name":   "socks-proxy",
					"type":   "socks5",
					"server": "127.0.0.1",
					"port":   socksPort,
				},
			},
		},
	})
	clientOpts, err := SJSON.UnmarshalExtendedContext[option.Options](clientCtx, clientRaw)
	if err != nil {
		t.Fatalf("decode client options: %v", err)
	}
	clientBox, err := box.New(box.Options{Context: clientCtx, Options: clientOpts})
	if err != nil {
		t.Fatalf("create client box: %v", err)
	}
	if err := clientBox.Start(); err != nil {
		t.Fatalf("start client box: %v", err)
	}
	defer clientBox.Close()

	out, err := urltest.PickOutbound(clientBox.Outbound())
	if err != nil {
		t.Fatalf("PickOutbound failed: %v", err)
	}
	if out.Tag() != "proxy" {
		t.Fatalf("expected PickOutbound to prefer 'proxy' over 'direct', got %q", out.Tag())
	}

	latency, err := urltest.Test(out, target.URL, 5000, nil)
	if err != nil {
		t.Fatalf("URLTest through proxy failed: %v", err)
	}
	if latency < 1 {
		t.Fatalf("expected latency >= 1ms, got %d", latency)
	}
}

func TestConcurrentTestBoxesWhileCacheDBLocked(t *testing.T) {
	mihomobridge.Install(nil)

	// Switch to an isolated temp dir so the simulated :bg box creates cache.db here.
	tmpDir := t.TempDir()
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(origWD) }()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	// Start a simulated :bg box holding cache.db open with bbolt exclusive lock + SOCKS5 server.
	socksPort := freeTCPPort(t)
	bgCtx := box.Context(context.Background(), include.InboundRegistry(), include.OutboundRegistry(),
		include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry(), include.CertificateProviderRegistry())
	bgRaw, _ := json.Marshal(map[string]any{
		"log": map[string]any{"level": "error"},
		"experimental": map[string]any{
			"cache_file": map[string]any{
				"enabled": true,
				"path":    filepath.Join(tmpDir, "cache.db"),
			},
		},
		"inbounds": []any{map[string]any{
			"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": socksPort,
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	})
	bgOpts, err := SJSON.UnmarshalExtendedContext[option.Options](bgCtx, bgRaw)
	if err != nil {
		t.Fatalf("decode bg options: %v", err)
	}
	bgBox, err := box.New(box.Options{Context: bgCtx, Options: bgOpts})
	if err != nil {
		t.Fatalf("create bg box: %v", err)
	}
	if err := bgBox.Start(); err != nil {
		t.Fatalf("start bg box: %v", err)
	}
	defer bgBox.Close()

	// Launch 5 concurrent test boxes in the same directory WITHOUT PlatformLogWriter/CacheFile.
	// Before the v1.5.2 fix, passing PlatformLogWriter != nil triggered CacheFile on every test
	// box, causing bbolt flock timeouts/failures against :bg and sibling workers.
	const workers = 5
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			outbounds := include.OutboundRegistry()
			mihomobridge.Register(outbounds)
			ctx := box.Context(context.Background(), include.InboundRegistry(), outbounds,
				include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry(), include.CertificateProviderRegistry())
			raw, _ := json.Marshal(map[string]any{
				"log": map[string]any{"level": "error"},
				"outbounds": []any{
					map[string]any{
						"type": "mihomo",
						"tag":  "proxy",
						"proxy": map[string]any{
							"name":   "socks-proxy",
							"type":   "socks5",
							"server": "127.0.0.1",
							"port":   socksPort,
						},
					},
					map[string]any{"type": "direct", "tag": "direct"},
				},
			})
			opts, err := SJSON.UnmarshalExtendedContext[option.Options](ctx, raw)
			if err != nil {
				errs <- err
				return
			}
			instance, err := box.New(box.Options{Context: ctx, Options: opts, PlatformLogWriter: nil})
			if err != nil {
				errs <- err
				return
			}
			if err := instance.Start(); err != nil {
				_ = instance.Close()
				errs <- err
				return
			}
			defer instance.Close()
			out, err := urltest.PickOutbound(instance.Outbound())
			if err != nil {
				errs <- err
				return
			}
			latency, err := urltest.Test(out, target.URL, 5000, nil)
			if err != nil {
				errs <- err
				return
			}
			if latency < 1 {
				errs <- os.ErrInvalid
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent test box failed while cache.db was locked: %v", err)
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("alloc free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
