package boxconfig

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"nekobox-mac/internal/hysteriapin"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	SJSON "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
)

func TestTUICV5Transports(t *testing.T) {
	const id = "02d42cc5-abe3-4f76-b826-41e1663ddc8e"
	httpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(httpServer.Close)
	tlsCertificate := httpServer.TLS.Certificates[0]
	privateKey, err := x509.MarshalPKCS8PrivateKey(tlsCertificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(tlsCertificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)

	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := socket.LocalAddr().(*net.UDPAddr).Port
	socket.Close()
	startBox(t, object{
		"log": object{"disabled": true},
		"inbounds": []object{{
			"type": "tuic", "listen": "127.0.0.1", "listen_port": port,
			"congestion_control": "new_reno", "zero_rtt_handshake": true, "heartbeat": "250ms",
			"users": []object{{"uuid": id, "password": "fixture"}},
			"tls": object{
				"enabled":     true,
				"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsCertificate.Certificate[0]})),
				"key":         string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey})),
			},
		}},
		"outbounds": []object{{"type": "direct"}},
	})

	for _, mode := range []string{"native", "quic", "udp_over_stream"} {
		t.Run(mode, func(t *testing.T) {
			outbound := object{
				"type": "tuic", "server": "127.0.0.1", "server_port": port,
				"uuid": id, "password": "fixture", "congestion_control": "new_reno",
				"zero_rtt_handshake": true, "heartbeat": "250ms",
				"initial_packet_size": 1280, "disable_path_mtu_discovery": true,
				"tls": object{
					"enabled": true, "server_name": "example.com",
					"certificate_public_key_sha256": []string{base64.StdEncoding.EncodeToString(pin[:])},
				},
			}
			if mode == "udp_over_stream" {
				outbound["udp_over_stream"] = true
			} else {
				outbound["udp_relay_mode"] = mode
			}
			instance := startBox(t, object{"log": object{"disabled": true}, "outbounds": []object{outbound}})
			dialer := instance.Outbound().Default()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			httpTransport := httpServer.Client().Transport.(*http.Transport).Clone()
			httpTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
			}
			defer httpTransport.CloseIdleConnections()
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, httpServer.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := (&http.Client{Transport: httpTransport}).Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusNoContent {
				t.Fatalf("HTTP status through TUIC: %d", response.StatusCode)
			}
			echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				buf := make([]byte, 32)
				n, addr, err := echo.ReadFrom(buf)
				if err == nil {
					echo.WriteTo(buf[:n], addr)
				}
			}()
			address := M.ParseSocksaddr(echo.LocalAddr().String())
			packets, err := dialer.ListenPacket(ctx, address)
			if err != nil {
				t.Fatal(err)
			}
			defer packets.Close()
			if err := packets.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := packets.WriteTo([]byte("tuic"), address); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 32)
			n, _, err := packets.ReadFrom(buf)
			if err != nil || string(buf[:n]) != "tuic" {
				t.Fatalf("UDP reply via %s: %q, %v", mode, buf[:n], err)
			}
		})
	}
}

func startBox(t *testing.T, config object) *box.Box {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	outbounds := include.OutboundRegistry()
	hysteriapin.Register(outbounds)
	ctx := box.Context(context.Background(), include.InboundRegistry(), outbounds, include.EndpointRegistry(),
		include.DNSTransportRegistry(), include.ServiceRegistry(), include.CertificateProviderRegistry())
	options, err := SJSON.UnmarshalExtendedContext[option.Options](ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	return instance
}
