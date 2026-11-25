// SPDX-License-Identifier: GPL-3.0-or-later
package xraybridge

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	SJSON "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/proxy/freedom"
)

func TestXHTTPShareAndTraffic(t *testing.T) {
	const id = "02d42cc5-abe3-4f76-b826-41e1663ddc8e"
	if err := Install(nil); err != nil {
		t.Fatal(err)
	}
	address := availableAddress(t)
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	serverJSON := fmt.Sprintf(`{
		"log":{"loglevel":"none"},
		"inbounds":[{"listen":"127.0.0.1","port":%s,"protocol":"vless",
			"settings":{"clients":[{"id":%q}],"decryption":"none"},
			"streamSettings":{"network":"xhttp","security":"none","xhttpSettings":{"path":"/next"}}}],
		"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}]
	}`, port, id)
	serverConfig, err := serial.LoadJSONConfig(strings.NewReader(serverJSON))
	if err != nil {
		t.Fatal(err)
	}
	server, err := core.New(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}

	link := fmt.Sprintf("vless://%s@%s?encryption=none&type=xhttp&path=%%2Fnext&mode=packet-up#XHTTP", id, address)
	profile, err := ParseShareLink(link)
	if err != nil || profile == "" {
		t.Fatalf("import XHTTP profile: %v", err)
	}
	shared, err := ShareLink(profile, "XHTTP")
	if err != nil {
		t.Fatal(err)
	}
	profile, err = ParseShareLink(shared)
	if err != nil || profile == "" {
		t.Fatalf("re-import XHTTP profile: %v", err)
	}

	registry := include.OutboundRegistry()
	Register(registry)
	ctx := box.Context(context.Background(), include.InboundRegistry(), registry,
		include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry(),
		include.CertificateProviderRegistry())
	options, err := SJSON.UnmarshalExtendedContext[option.Options](ctx, []byte(`{"outbounds":[`+profile+`]}`))
	if err != nil {
		t.Fatal(err)
	}
	client, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	out := client.Outbound().Default()
	bridge := out.(*xrayOutbound)
	if bridge.instance != nil {
		t.Fatal("the Xray handler started before the first connection")
	}
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return out.DialContext(ctx, network, M.ParseSocksaddr(addr))
		},
	}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 8 * time.Second}).Get(destination.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if bridge.instance == nil {
		t.Fatal("the Xray handler did not start on demand")
	}
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("HTTP through Xray: %d", response.StatusCode)
	}

	udpEcho, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		buffer := make([]byte, 128)
		if n, from, err := udpEcho.ReadFrom(buffer); err == nil {
			udpEcho.WriteTo(buffer[:n], from)
		}
	}()
	udpTarget := M.ParseSocksaddr(udpEcho.LocalAddr().String())
	packet, err := out.ListenPacket(ctx, udpTarget)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	if err := packet.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := packet.WriteTo([]byte("nekobox"), udpTarget); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	n, _, err := packet.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "nekobox" {
		t.Fatalf("UDP through Xray: %q, %v", buffer[:n], err)
	}
}

func availableAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}
