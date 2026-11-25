// SPDX-License-Identifier: GPL-3.0-or-later
package mihomobridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync"

	mihomoadapter "github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
	MM "github.com/metacubex/sing/common/metadata"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const Type = "mihomo"

type Options struct {
	Proxy map[string]any `json:"proxy"`
	option.DialerOptions
}

func Register(registry *outbound.Registry) {
	outbound.Register[Options](registry, Type, newOutbound)
}

func Version() string {
	if C.Version != "" && C.Version != "1.10.0" {
		return C.Version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/metacubex/mihomo" && dep.Version != "" {
				return dep.Version
			}
		}
	}
	return C.Version
}

func supportsType(proxyType string) bool {
	switch strings.ToLower(strings.TrimSpace(proxyType)) {
	case "trusttunnel", "sudoku", "shadowquic", "masque", "mieru", "snell",
		"ss", "ssr", "socks5", "http", "vmess", "vless", "trojan",
		"hysteria", "hysteria2", "wireguard", "tuic", "ssh", "anytls",
		"openvpn", "gost-relay", "tailscale", "zerotier", "easytier":
		return true
	default:
		return false
	}
}

func normalizeMapping(raw map[string]any, defaultName string) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, errors.New("Mihomo proxy configuration is required")
	}
	mapping := make(map[string]any, len(raw)+1)
	for k, v := range raw {
		mapping[k] = v
	}
	proxyType, _ := mapping["type"].(string)
	proxyType = strings.ToLower(strings.TrimSpace(proxyType))
	if !supportsType(proxyType) {
		return nil, fmt.Errorf("unsupported Mihomo proxy type %q", proxyType)
	}
	mapping["type"] = proxyType
	if proxyType == "masque" {
		if err := normalizeMasqueMapping(mapping); err != nil {
			return nil, err
		}
	}
	if name, _ := mapping["name"].(string); strings.TrimSpace(name) == "" {
		if defaultName == "" {
			defaultName = "mihomo"
		}
		mapping["name"] = defaultName
	}
	return mapping, nil
}

func ValidateConfig(config string) error {
	var options Options
	if err := json.Unmarshal([]byte(config), &options); err != nil {
		return fmt.Errorf("invalid Mihomo configuration: %w", err)
	}
	mapping, err := normalizeMapping(options.Proxy, "validate")
	if err != nil {
		return err
	}
	proxy, err := mihomoadapter.ParseProxy(mapping)
	if err != nil {
		return fmt.Errorf("validate Mihomo proxy: %w", err)
	}
	_ = proxy.Close()
	return nil
}

func WrapProxy(raw string) (string, error) {
	var proxyMap map[string]any
	if err := json.Unmarshal([]byte(raw), &proxyMap); err != nil {
		return "", fmt.Errorf("decode Mihomo proxy: %w", err)
	}
	mapping, err := normalizeMapping(proxyMap, "")
	if err != nil {
		return "", err
	}
	proxy, err := mihomoadapter.ParseProxy(mapping)
	if err != nil {
		return "", fmt.Errorf("parse Mihomo proxy: %w", err)
	}
	_ = proxy.Close()
	wrapped, err := json.Marshal(struct {
		Type  string         `json:"type"`
		Proxy map[string]any `json:"proxy"`
	}{Type: Type, Proxy: mapping})
	return string(wrapped), err
}

type mihomoOutbound struct {
	outbound.Adapter
	proxy     C.Proxy
	dnsRouter adapter.DNSRouter
	dnsHolder *dnsRouterHolder
	closeOnce sync.Once
}

func newOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options Options) (adapter.Outbound, error) {
	mapping, err := normalizeMapping(options.Proxy, tag)
	if err != nil {
		return nil, err
	}
	ipDialer, err := dialer.New(ctx, options.DialerOptions, false)
	if err != nil {
		return nil, err
	}
	domainDialer, err := dialer.New(ctx, options.DialerOptions, true)
	if err != nil {
		return nil, err
	}
	dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
	dnsHolder := setActiveDNSRouter(dnsRouter)
	proxy, err := mihomoadapter.ParseProxy(
		mapping,
		mihomoadapter.WithDialerForAPI(&singBoxDialer{
			ip:        ipDialer,
			domain:    domainDialer,
			dnsRouter: dnsRouter,
		}),
	)
	if err != nil {
		clearActiveDNSRouter(dnsHolder)
		return nil, fmt.Errorf("create Mihomo outbound: %w", err)
	}
	networks := []string{N.NetworkTCP}
	if proxy.SupportUDP() {
		networks = append(networks, N.NetworkUDP)
	}
	return &mihomoOutbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(Type, tag, networks, options.DialerOptions),
		proxy:     proxy,
		dnsRouter: dnsRouter,
		dnsHolder: dnsHolder,
	}, nil
}

func (o *mihomoOutbound) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	if stage == adapter.StartStateStart && o.dnsRouter != nil && o.dnsHolder == nil {
		o.dnsHolder = setActiveDNSRouter(o.dnsRouter)
	}
	return nil
}

func (o *mihomoOutbound) Close() error {
	var err error
	o.closeOnce.Do(func() {
		clearActiveDNSRouter(o.dnsHolder)
		if o.proxy != nil {
			err = o.proxy.Close()
		}
	})
	return err
}

func toMihomoMetadata(network C.NetWork, destination M.Socksaddr) *C.Metadata {
	meta := &C.Metadata{
		NetWork: network,
		Type:    C.INNER,
		DstPort: destination.Port,
	}
	if destination.IsIP() {
		meta.DstIP = destination.Addr.Unmap()
	} else {
		meta.Host = destination.Fqdn
	}
	return meta
}

func (o *mihomoOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx = withDNSRouter(ctx, o.dnsRouter)
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return o.proxy.DialContext(ctx, toMihomoMetadata(C.TCP, destination))
	case N.NetworkUDP:
		pc, err := o.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(pc, destination), nil
	default:
		return nil, fmt.Errorf("unsupported Mihomo network %q", network)
	}
}

func (o *mihomoOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !o.proxy.SupportUDP() {
		return nil, errors.New("Mihomo outbound does not support UDP")
	}
	ctx = withDNSRouter(ctx, o.dnsRouter)
	pc, err := o.proxy.ListenPacketContext(ctx, toMihomoMetadata(C.UDP, destination))
	if err != nil {
		return nil, err
	}
	return &mihomoPacketConn{PacketConn: pc}, nil
}

type mihomoPacketConn struct {
	C.PacketConn
}

func (c *mihomoPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err != nil || addr == nil {
		return n, addr, err
	}
	switch typed := addr.(type) {
	case *net.UDPAddr:
		return n, M.SocksaddrFromNet(typed), nil
	case MM.Socksaddr:
		if typed.IsIP() {
			return n, M.SocksaddrFrom(typed.Addr.Unmap(), typed.Port), nil
		}
		return n, M.Socksaddr{Fqdn: typed.Fqdn, Port: typed.Port}, nil
	default:
		return n, M.ParseSocksaddr(addr.String()), nil
	}
}

func (c *mihomoPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, errors.New("nil UDP destination")
	}
	switch typed := addr.(type) {
	case M.Socksaddr:
		if typed.IsIP() {
			return c.PacketConn.WriteTo(p, typed.UDPAddr())
		}
		return c.PacketConn.WriteTo(p, MM.Socksaddr{Fqdn: typed.Fqdn, Port: typed.Port})
	case *net.UDPAddr:
		return c.PacketConn.WriteTo(p, typed)
	default:
		if ap, err := netip.ParseAddrPort(addr.String()); err == nil {
			return c.PacketConn.WriteTo(p, net.UDPAddrFromAddrPort(ap))
		}
		return c.PacketConn.WriteTo(p, MM.ParseSocksaddr(addr.String()))
	}
}
