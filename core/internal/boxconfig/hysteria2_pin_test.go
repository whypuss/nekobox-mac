//go:build with_quic

package boxconfig

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestHysteria2CertificatePin(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	tlsCert := target.TLS.Certificates[0]
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(tlsCert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	renewal := *leaf
	renewal.SerialNumber = new(big.Int).Add(leaf.SerialNumber, big.NewInt(1))
	reissued, err := x509.CreateCertificate(rand.Reader, &renewal, &renewal, leaf.PublicKey, tlsCert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	leafHash, reissuedHash := sha256.Sum256(leaf.Raw), sha256.Sum256(reissued)
	pin, wrongPin := hex.EncodeToString(leafHash[:]), hex.EncodeToString(reissuedHash[:])

	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := socket.LocalAddr().(*net.UDPAddr).Port
	socket.Close()
	obfs := object{"type": "gecko", "password": "obfs-fixture", "min_packet_size": 512, "max_packet_size": 1024}
	startBox(t, object{
		"log": object{"disabled": true},
		"inbounds": []object{{
			"type": "hysteria2", "listen": "127.0.0.1", "listen_port": port,
			"users": []object{{"password": "fixture"}},
			"obfs":  obfs,
			"tls": object{
				"enabled":     true,
				"certificate": certificate,
				"key":         string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})),
			},
		}},
		"outbounds": []object{{"type": "direct"}},
	})

	for _, tc := range []struct {
		name, pin, serverName, wantError string
		root, insecure, standardTLS      bool
	}{
		{name: "unpinned", root: true},
		{name: "correct pin and trusted certificate", pin: pin, root: true},
		{name: "correct pin with insecure enabled", pin: pin, insecure: true},
		{name: "correct pin with ChromeParrot disabled", pin: pin, root: true, standardTLS: true},
		{name: "wrong pin even with trust", pin: wrongPin, root: true, wantError: "does not match pinSHA256"},
		{name: "wrong pin with insecure enabled", pin: wrongPin, insecure: true, wantError: "does not match pinSHA256"},
		{name: "correct pin and untrusted certificate", pin: pin, wantError: "unknown authority"},
		{name: "correct pin and wrong server name", pin: pin, root: true, serverName: "wrong.invalid", wantError: "wrong.invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tls := object{"enabled": true, "insecure": tc.insecure, "server_name": tc.serverName}
			if tc.root {
				tls["certificate"] = certificate
			}
			client := startBox(t, object{
				"log": object{"disabled": true},
				"outbounds": []object{{
					"type": "hysteria2", "server": "127.0.0.1", "server_port": port,
					"password": "fixture", "obfs": obfs, "pin_sha256": tc.pin, "tls": tls,
					"disable_chrome_parrot": tc.standardTLS,
				}},
			})
			dialer := client.Outbound().Default()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			transport := target.Client().Transport.(*http.Transport).Clone()
			defer transport.CloseIdleConnections()
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := (&http.Client{Transport: transport}).Do(request)
			if response != nil {
				response.Body.Close()
			}
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("got %v, want a TLS error containing %q", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusNoContent {
				t.Fatalf("HTTP status through Hysteria 2: %d", response.StatusCode)
			}
			if tc.pin != "" {
				checkHysteria2Datagram(t, ctx, dialer)
			}
		})
	}
}

func checkHysteria2Datagram(t *testing.T, ctx context.Context, dialer N.Dialer) {
	t.Helper()
	echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		var buf [32]byte
		n, addr, err := echo.ReadFrom(buf[:])
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
	if _, err := packets.WriteTo([]byte("hysteria2"), address); err != nil {
		t.Fatal(err)
	}
	var buf [32]byte
	n, _, err := packets.ReadFrom(buf[:])
	if err != nil || string(buf[:n]) != "hysteria2" {
		t.Fatalf("UDP reply through Hysteria 2: %q, %v", buf[:n], err)
	}
}
