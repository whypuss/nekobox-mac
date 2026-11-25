// SPDX-License-Identifier: GPL-3.0-or-later
package mihomobridge

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"

	mihomodialer "github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	_ "github.com/metacubex/mihomo/dns"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	SBC "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type dnsRouterKey struct{}

var (
	activeDNSRoutersMu sync.RWMutex
	activeDNSRouters   []*dnsRouterHolder
)

type dnsRouterHolder struct {
	router adapter.DNSRouter
}

// Install configures Android VPN socket protection and routes Mihomo DNS
// resolution through sing-box's DNSRouter so lookups work without /etc/resolv.conf.
func Install(protect func(int) error) {
	if protect != nil {
		mihomodialer.DefaultSocketHook = func(_, _ string, raw syscall.RawConn) error {
			var protectErr error
			if err := raw.Control(func(fd uintptr) { protectErr = protect(int(fd)) }); err != nil {
				return err
			}
			return protectErr
		}
	}
	resolver.DisableIPv6 = false
	r := &singBoxResolver{}
	resolver.DefaultResolver = r
	resolver.ProxyServerHostResolver = r
	resolver.DirectHostResolver = r
}

func setActiveDNSRouter(router adapter.DNSRouter) *dnsRouterHolder {
	if router == nil {
		return nil
	}
	holder := &dnsRouterHolder{router: router}
	activeDNSRoutersMu.Lock()
	activeDNSRouters = append(activeDNSRouters, holder)
	activeDNSRoutersMu.Unlock()
	return holder
}

func clearActiveDNSRouter(holder *dnsRouterHolder) {
	if holder == nil {
		return
	}
	activeDNSRoutersMu.Lock()
	for i := len(activeDNSRouters) - 1; i >= 0; i-- {
		if activeDNSRouters[i] == holder {
			activeDNSRouters = append(activeDNSRouters[:i], activeDNSRouters[i+1:]...)
			break
		}
	}
	activeDNSRoutersMu.Unlock()
}

func withDNSRouter(ctx context.Context, router adapter.DNSRouter) context.Context {
	if router == nil {
		return ctx
	}
	return context.WithValue(ctx, dnsRouterKey{}, router)
}

func dnsRouterFromContext(ctx context.Context) adapter.DNSRouter {
	if router, ok := ctx.Value(dnsRouterKey{}).(adapter.DNSRouter); ok && router != nil {
		return router
	}
	activeDNSRoutersMu.RLock()
	var router adapter.DNSRouter
	if n := len(activeDNSRouters); n > 0 {
		router = activeDNSRouters[n-1].router
	}
	activeDNSRoutersMu.RUnlock()
	return router
}

type singBoxResolver struct{}

func (r *singBoxResolver) lookup(ctx context.Context, host string, strategy SBC.DomainStrategy, netNetwork string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if strategy == SBC.DomainStrategyIPv4Only && !ip.Is4() {
			return nil, resolver.ErrIPVersion
		}
		if strategy == SBC.DomainStrategyIPv6Only && !ip.Is6() {
			return nil, resolver.ErrIPVersion
		}
		return []netip.Addr{ip}, nil
	}
	if router := dnsRouterFromContext(ctx); router != nil {
		addrs, err := router.Lookup(ctx, host, adapter.DNSQueryOptions{Strategy: strategy})
		if err == nil && len(addrs) > 0 {
			return addrs, nil
		}
	}
	return net.DefaultResolver.LookupNetIP(ctx, netNetwork, host)
}

func (r *singBoxResolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookup(ctx, host, SBC.DomainStrategyAsIS, "ip")
}

func (r *singBoxResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookup(ctx, host, SBC.DomainStrategyIPv4Only, "ip4")
}

func (r *singBoxResolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookup(ctx, host, SBC.DomainStrategyIPv6Only, "ip6")
}

func (r *singBoxResolver) ResolveECH(ctx context.Context, host string) ([]byte, error) {
	return nil, errors.New("ECH DNS query unsupported via Mihomo bridge resolver")
}

func (r *singBoxResolver) ExchangeContext(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	if router := dnsRouterFromContext(ctx); router != nil {
		return router.Exchange(ctx, m, adapter.DNSQueryOptions{})
	}
	return nil, errors.New("no active sing-box DNS router")
}

// Invalid follows Mihomo's Resolver convention where true means the resolver is active.
func (r *singBoxResolver) Invalid() bool    { return true }
func (r *singBoxResolver) ClearCache()      {}
func (r *singBoxResolver) ResetConnection() {}

type singBoxDialer struct {
	ip        N.Dialer
	domain    N.Dialer
	dnsRouter adapter.DNSRouter
}

var _ C.Dialer = (*singBoxDialer)(nil)

func (d *singBoxDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ctx = withDNSRouter(ctx, d.dnsRouter)
	destination := M.ParseSocksaddr(address)
	targetDialer := d.ip
	if destination.IsFqdn() {
		targetDialer = d.domain
	}
	return targetDialer.DialContext(ctx, network, destination)
}

func (d *singBoxDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	ctx = withDNSRouter(ctx, d.dnsRouter)
	var destination M.Socksaddr
	if rAddrPort.IsValid() {
		destination = M.SocksaddrFromNetIP(rAddrPort)
	} else if address != "" {
		destination = M.ParseSocksaddr(address)
	} else if network == "udp6" {
		destination = M.SocksaddrFrom(netip.IPv6Unspecified(), 0)
	} else {
		destination = M.SocksaddrFrom(netip.IPv4Unspecified(), 0)
	}
	targetDialer := d.ip
	if destination.IsFqdn() {
		targetDialer = d.domain
	}
	return targetDialer.ListenPacket(ctx, destination)
}
