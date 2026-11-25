// SPDX-License-Identifier: GPL-3.0-or-later
package mihomobridge_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"nekobox-mac/internal/mihomobridge"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/sudoku"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	SJSON "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func testECDSAP256Keys(t *testing.T) (privB64, pubB64 string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	privDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(privDER), base64.StdEncoding.EncodeToString(pubDER)
}

func TestValidateNewMihomoProtocols(t *testing.T) {
	mihomobridge.Install(nil)

	privKey, pubKey := testECDSAP256Keys(t)
	wgPrivRaw := make([]byte, 32)
	wgPubRaw := make([]byte, 32)
	if _, err := rand.Read(wgPrivRaw); err != nil {
		t.Fatalf("generate wg private key: %v", err)
	}
	if _, err := rand.Read(wgPubRaw); err != nil {
		t.Fatalf("generate wg public key: %v", err)
	}
	wgPrivB64 := base64.StdEncoding.EncodeToString(wgPrivRaw)
	wgPubB64 := base64.StdEncoding.EncodeToString(wgPubRaw)
	sudokuPriv, _, err := sudoku.GenKeyPair()
	if err != nil {
		t.Fatalf("generate sudoku keypair: %v", err)
	}

	cases := []struct {
		name  string
		proxy map[string]any
	}{
		{
			name: "trusttunnel_h2",
			proxy: map[string]any{
				"name":             "tt-h2",
				"type":             "trusttunnel",
				"server":           "127.0.0.1",
				"port":             8443,
				"username":         "user",
				"password":         "pass",
				"sni":              "tt.example.test",
				"skip-cert-verify": true,
				"udp":              true,
			},
		},
		{
			name: "trusttunnel_quic",
			proxy: map[string]any{
				"name":                  "tt-quic",
				"type":                  "trusttunnel",
				"server":                "127.0.0.1",
				"port":                  8443,
				"username":              "user",
				"password":              "pass",
				"sni":                   "tt.example.test",
				"quic":                  true,
				"congestion-controller": "bbr",
				"skip-cert-verify":      true,
				"udp":                   true,
			},
		},
		{
			name: "sudoku",
			proxy: map[string]any{
				"name":                 "sudoku-node",
				"type":                 "sudoku",
				"server":               "127.0.0.1",
				"port":                 443,
				"key":                  sudokuPriv,
				"aead-method":          "aes-128-gcm",
				"table-type":           "prefer_ascii",
				"padding-min":          5,
				"padding-max":          15,
				"enable-pure-downlink": true,
				"http-mask":            true,
				"http-mask-mode":       "auto",
			},
		},
		{
			name: "shadowquic",
			proxy: map[string]any{
				"name":                  "sq-node",
				"type":                  "shadowquic",
				"server":                "127.0.0.1",
				"port":                  443,
				"username":              "user",
				"password":              "pass",
				"sni":                   "sq.example.test",
				"alpn":                  []string{"h3"},
				"congestion-controller": "bbr",
				"zero-rtt":              true,
			},
		},
		{
			name: "masque",
			proxy: map[string]any{
				"name":             "masque-warp",
				"type":             "masque",
				"server":           "162.159.198.1",
				"port":             443,
				"private-key":      privKey,
				"public-key":       pubKey,
				"ip":               "172.16.0.2",
				"mtu":              1280,
				"udp":              true,
				"skip-cert-verify": true,
			},
		},
		{
			name: "mieru",
			proxy: map[string]any{
				"name":         "mieru-native",
				"type":         "mieru",
				"server":       "127.0.0.1",
				"port":         10000,
				"transport":    "TCP",
				"username":     "user",
				"password":     "pass",
				"multiplexing": "MULTIPLEXING_LOW",
				"udp":          true,
			},
		},
		{
			name: "snell_v4",
			proxy: map[string]any{
				"name":    "snell-v4",
				"type":    "snell",
				"server":  "127.0.0.1",
				"port":    6160,
				"psk":     "secret-psk-123456",
				"version": 4,
				"udp":     true,
				"obfs-opts": map[string]any{
					"mode": "http",
					"host": "bing.com",
				},
			},
		},
		{
			name: "amneziawg",
			proxy: map[string]any{
				"name":        "awg-node",
				"type":        "wireguard",
				"server":      "127.0.0.1",
				"port":        51820,
				"ip":          "10.8.0.2",
				"private-key": wgPrivB64,
				"public-key":  wgPubB64,
				"mtu":         1280,
				"udp":         true,
				"amnezia-wg-option": map[string]any{
					"jc":   4,
					"jmin": 40,
					"jmax": 70,
					"s1":   20,
					"s2":   30,
					"h1":   "100001",
					"h2":   "200002",
					"h3":   "300003",
					"h4":   "400004",
				},
			},
		},
		{
			name: "ssr",
			proxy: map[string]any{
				"name":           "ssr-legacy",
				"type":           "ssr",
				"server":         "127.0.0.1",
				"port":           8388,
				"cipher":         "aes-256-cfb",
				"password":       "secret-pass",
				"obfs":           "tls1.2_ticket_auth",
				"obfs-param":     "cloudfront.com",
				"protocol":       "auth_aes128_md5",
				"protocol-param": "1001:token",
				"udp":            true,
			},
		},
		{
			name: "ssh",
			proxy: map[string]any{
				"name":     "ssh-mihomo",
				"type":     "ssh",
				"server":   "127.0.0.1",
				"port":     22,
				"username": "root",
				"password": "secret",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.proxy)
			if err != nil {
				t.Fatalf("marshal proxy: %v", err)
			}
			wrapped, err := mihomobridge.WrapProxy(string(raw))
			if err != nil {
				t.Fatalf("WrapProxy(%s) failed: %v", tc.name, err)
			}
			if err := mihomobridge.ValidateConfig(wrapped); err != nil {
				t.Fatalf("ValidateConfig(%s) failed: %v", tc.name, err)
			}
		})
	}

	if err := mihomobridge.ValidateConfig(`{"type":"mihomo","proxy":{"type":"direct"}}`); err == nil {
		t.Fatal("expected disallowed proxy type 'direct' to fail validation")
	}
	if !strings.HasPrefix(mihomobridge.Version(), "v") && mihomobridge.Version() == "" {
		t.Fatalf("unexpected Mihomo version: %q", mihomobridge.Version())
	}
}

func TestMasqueKeyAndModeNormalization(t *testing.T) {
	mihomobridge.Install(nil)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8 private key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal PKIX public key: %v", err)
	}
	pkcs8PEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}))
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	rawURLPriv := base64.RawURLEncoding.EncodeToString(pkcs8DER)
	rawURLPub := base64.RawURLEncoding.EncodeToString(pubDER)

	cases := []struct {
		name  string
		proxy map[string]any
	}{
		{
			name: "pkcs8_pem_and_default_ip",
			proxy: map[string]any{
				"name":             "masque-pem",
				"type":             "masque",
				"server":           "162.159.198.1",
				"port":             443,
				"private_key":      pkcs8PEM,
				"endpoint_pub_key": pubPEM,
				"skip-cert-verify": true,
			},
		},
		{
			name: "rawurl_base64_h2_local_address",
			proxy: map[string]any{
				"name":          "masque-h2",
				"type":          "masque",
				"server":        "162.159.198.1",
				"port":          443,
				"private-key":   rawURLPriv,
				"public-key":    rawURLPub,
				"network":       "h2",
				"local_address": []string{"172.16.0.2/32", "2606:4700:110::2/128"},
			},
		},
		{
			name: "h3_l4proxy_without_local_ip",
			proxy: map[string]any{
				"name":             "masque-l4",
				"type":             "masque",
				"server":           "162.159.198.1",
				"port":             443,
				"private-key":      rawURLPriv,
				"public-key":       rawURLPub,
				"network":          "h3-l4proxy",
				"bbr-profile":      "standard",
				"cwnd":             32,
				"skip-cert-verify": true,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.proxy)
			if err != nil {
				t.Fatalf("marshal masque proxy: %v", err)
			}
			wrapped, err := mihomobridge.WrapProxy(string(raw))
			if err != nil {
				t.Fatalf("WrapProxy(%s) failed: %v", tc.name, err)
			}
			if err := mihomobridge.ValidateConfig(wrapped); err != nil {
				t.Fatalf("ValidateConfig(%s) failed: %v", tc.name, err)
			}
		})
	}
}

func TestMihomoBridgeSocks5TCPAndUDPTraffic(t *testing.T) {
	mihomobridge.Install(nil)

	// Start a real TCP echo server.
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echoListener.Close()
	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// Start a real sing-box SOCKS5 server (supports both TCP and UDP associate).
	serverCtx := box.Context(context.Background(), include.InboundRegistry(), include.OutboundRegistry(),
		include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry(), include.CertificateProviderRegistry())
	socksPort := freeTCPPort(t)
	serverCfg := map[string]any{
		"log": map[string]any{"level": "error"},
		"inbounds": []any{
			map[string]any{
				"type":        "socks",
				"tag":         "socks-in",
				"listen":      "127.0.0.1",
				"listen_port": socksPort,
			},
		},
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": "direct"},
		},
	}
	serverRaw, _ := json.Marshal(serverCfg)
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

	// Start a sing-box client using our mihomobridge outbound pointing at that SOCKS5 server.
	outbounds := include.OutboundRegistry()
	mihomobridge.Register(outbounds)
	clientCtx := box.Context(context.Background(), include.InboundRegistry(), outbounds,
		include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry(), include.CertificateProviderRegistry())
	clientCfg := map[string]any{
		"log": map[string]any{"level": "error"},
		"outbounds": []any{
			map[string]any{
				"type": "mihomo",
				"tag":  "proxy",
				"proxy": map[string]any{
					"name":   "test-socks",
					"type":   "socks5",
					"server": "127.0.0.1",
					"port":   socksPort,
					"udp":    true,
				},
			},
		},
	}
	clientRaw, _ := json.Marshal(clientCfg)
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

	proxyOutbound, ok := clientBox.Outbound().Outbound("proxy")
	if !ok {
		t.Fatal("missing proxy outbound")
	}

	// Test TCP echo through sing-box -> mihomobridge -> SOCKS5 -> echo server.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := proxyOutbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(echoListener.Addr().String()))
	if err != nil {
		t.Fatalf("TCP dial through mihomo bridge failed: %v", err)
	}
	defer conn.Close()
	want := "hello-mihomo-v1.19.34"
	if _, err := conn.Write([]byte(want)); err != nil {
		t.Fatalf("write TCP payload: %v", err)
	}
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read TCP echo: %v", err)
	}
	if string(buf) != want {
		t.Fatalf("TCP echo mismatch: got %q, want %q", string(buf), want)
	}

	// Test UDP echo through sing-box -> mihomobridge -> SOCKS5 -> UDP echo server.
	udpEcho, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp echo: %v", err)
	}
	defer udpEcho.Close()
	go func() {
		packet := make([]byte, 2048)
		for {
			n, addr, err := udpEcho.ReadFrom(packet)
			if err != nil {
				return
			}
			_, _ = udpEcho.WriteTo(packet[:n], addr)
		}
	}()

	udpTarget := M.ParseSocksaddr(udpEcho.LocalAddr().String())
	pc, err := proxyOutbound.ListenPacket(ctx, udpTarget)
	if err != nil {
		t.Fatalf("UDP listen through mihomo bridge failed: %v", err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
	udpWant := "udp-mihomo-echo"
	if _, err := pc.WriteTo([]byte(udpWant), udpTarget); err != nil {
		t.Fatalf("write UDP payload: %v", err)
	}
	udpBuf := make([]byte, 64)
	n, _, err := pc.ReadFrom(udpBuf)
	if err != nil {
		t.Fatalf("read UDP echo: %v", err)
	}
	if string(udpBuf[:n]) != udpWant {
		t.Fatalf("UDP echo mismatch: got %q, want %q", string(udpBuf[:n]), udpWant)
	}
}

func TestMihomoBridgeTrustTunnelHTTP2Connect(t *testing.T) {
	mihomobridge.Install(nil)

	// Local TCP echo target.
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echoListener.Close()
	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// Local HTTP/2 TLS CONNECT server matching TrustTunnel's HTTP/2 CONNECT tunnel.
	cert := selfSignedCert(t)
	h2Server := &http.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2"},
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
			if r.Header.Get("Proxy-Authorization") != expectedAuth {
				http.Error(w, "unauthorized", http.StatusProxyAuthRequired)
				return
			}
			targetConn, err := net.Dial("tcp", r.Host)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer targetConn.Close()
			w.WriteHeader(http.StatusOK)
			flusher := w.(http.Flusher)
			flusher.Flush()
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, _ = io.Copy(targetConn, r.Body)
			}()
			buf := make([]byte, 4096)
			for {
				n, err := targetConn.Read(buf)
				if n > 0 {
					if _, werr := w.Write(buf[:n]); werr != nil {
						break
					}
					flusher.Flush()
				}
				if err != nil {
					break
				}
			}
			<-done
		}),
	}
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen h2: %v", err)
	}
	tlsListener := tls.NewListener(rawListener, h2Server.TLSConfig)
	defer tlsListener.Close()
	go func() { _ = h2Server.Serve(tlsListener) }()
	defer h2Server.Close()

	_, portStr, _ := net.SplitHostPort(rawListener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	outbounds := include.OutboundRegistry()
	mihomobridge.Register(outbounds)
	clientCtx := box.Context(context.Background(), include.InboundRegistry(), outbounds,
		include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry(), include.CertificateProviderRegistry())
	clientCfg := map[string]any{
		"log": map[string]any{"level": "error"},
		"outbounds": []any{
			map[string]any{
				"type": "mihomo",
				"tag":  "proxy",
				"proxy": map[string]any{
					"name":             "tt-local",
					"type":             "trusttunnel",
					"server":           "127.0.0.1",
					"port":             port,
					"username":         "alice",
					"password":         "secret",
					"sni":              "localhost",
					"skip-cert-verify": true,
					"udp":              false,
				},
			},
		},
	}
	clientRaw, _ := json.Marshal(clientCfg)
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

	proxyOutbound, _ := clientBox.Outbound().Outbound("proxy")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := proxyOutbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(echoListener.Addr().String()))
	if err != nil {
		t.Fatalf("TrustTunnel dial failed: %v", err)
	}
	defer conn.Close()
	want := "trusttunnel-h2-verified"
	if _, err := conn.Write([]byte(want)); err != nil {
		t.Fatalf("write TrustTunnel payload: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read TrustTunnel echo: %v", err)
	}
	if string(got) != want {
		t.Fatalf("TrustTunnel echo mismatch: got %q, want %q", string(got), want)
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

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate cert key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create self-signed cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
