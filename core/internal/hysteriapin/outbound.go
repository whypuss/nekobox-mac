// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from sing-box v1.14.4 protocol/hysteria2/outbound.go.
// Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

//go:build with_quic

package hysteriapin

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	boxhysteria2 "github.com/sagernet/sing-box/protocol/hysteria2"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing-quic/hysteria2/realm"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type outboundOptions struct {
	option.Hysteria2OutboundOptions
	PinSHA256 string `json:"pin_sha256,omitempty"`
}

func Register(registry *outbound.Registry) {
	outbound.Register(registry, C.TypeHysteria2, newOutbound)
}

var (
	_ adapter.Outbound                = (*pinnedOutbound)(nil)
	_ adapter.InterfaceUpdateListener = (*pinnedOutbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*pinnedOutbound)(nil)
	_ adapter.OutboundWithMultiplex   = (*pinnedOutbound)(nil)
)

type pinnedOutbound struct {
	outbound.Adapter
	logger log.ContextLogger
	client *hysteria2.Client
}

func newOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, config outboundOptions) (adapter.Outbound, error) {
	options := config.Hysteria2OutboundOptions
	if config.PinSHA256 == "" {
		return boxhysteria2.NewOutbound(ctx, router, logger, tag, options)
	}
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	pinText := strings.NewReplacer(":", "", "-", "").Replace(strings.TrimSpace(config.PinSHA256))
	pin, err := hex.DecodeString(pinText)
	if err != nil || len(pin) != sha256.Size {
		return nil, E.New("Hysteria 2 pinSHA256 must contain 64 hexadecimal digits")
	}
	serverName, err := tlsServerAddress(options)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := tls.NewClient(ctx, logger, serverName, *options.TLS)
	if err != nil {
		return nil, err
	}
	// Hysteria 2 uses this standard config for its QUIC handshake.
	stdConfig, err := tlsConfig.STDConfig()
	if err != nil {
		return nil, E.Cause(err, "configure Hysteria 2 pinSHA256")
	}
	pinCertificate(stdConfig, [sha256.Size]byte(pin))

	realmSTUNServersIsDomain := options.Realm != nil && options.Realm.STUNServersIsDomain()
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:          ctx,
		Options:          options.DialerOptions,
		RemoteIsDomain:   options.ServerIsDomain() || realmSTUNServersIsDomain,
		ResolverOnDetour: realmSTUNServersIsDomain,
		NewDialer:        realmSTUNServersIsDomain,
	})
	if err != nil {
		return nil, err
	}
	networkList := options.Network.Build()
	clientOptions := hysteria2.ClientOptions{
		Context:        ctx,
		Dialer:         outboundDialer,
		Logger:         logger,
		BrutalDebug:    options.BrutalDebug,
		ServerAddress:  options.ServerOptions.Build(),
		ServerPorts:    options.ServerPorts,
		HopInterval:    time.Duration(options.HopInterval),
		HopIntervalMax: time.Duration(options.HopIntervalMax),
		SendBPS:        uint64(options.UpMbps * hysteria.MbpsToBps),
		ReceiveBPS:     uint64(options.DownMbps * hysteria.MbpsToBps),
		Password:       options.Password,
		TLSConfig:      tlsConfig,
		QUICOptions: qtls.QUICOptions{
			IdleTimeout:             options.IdleTimeout.Build(),
			KeepAlivePeriod:         options.KeepAlivePeriod.Build(),
			StreamReceiveWindow:     options.StreamReceiveWindow.Value(),
			ConnectionReceiveWindow: options.ConnectionReceiveWindow.Value(),
			MaxConcurrentStreams:    options.MaxConcurrentStreams,
			InitialPacketSize:       options.InitialPacketSize,
			DisablePathMTUDiscovery: options.DisablePathMTUDiscovery,
		},
		UDPDisabled:  !common.Contains(networkList, N.NetworkUDP),
		BBRProfile:   options.BBRProfile,
		ChromeParrot: !options.DisableChromeParrot,
	}
	if options.Obfs != nil {
		if options.Obfs.Password == "" {
			return nil, E.New("missing obfs password")
		}
		switch options.Obfs.Type {
		case hysteria2.ObfsTypeSalamander:
			clientOptions.SalamanderPassword = options.Obfs.Password
		case hysteria2.ObfsTypeGecko:
			clientOptions.GeckoPassword = options.Obfs.Password
			clientOptions.GeckoMinPacketSize = options.Obfs.GeckoOptions.MinPacketSize
			clientOptions.GeckoMaxPacketSize = options.Obfs.GeckoOptions.MaxPacketSize
		default:
			return nil, E.New("unknown obfs type: ", options.Obfs.Type)
		}
	}
	if options.Realm != nil {
		var queryOptions adapter.DNSQueryOptions
		if realmSTUNServersIsDomain {
			queryOptions = outboundDialer.(dialer.ResolveDialer).QueryOptions()
		}
		clientOptions.RealmOptions, err = newRealmOptions(ctx, logger, options.Realm, queryOptions)
		if err != nil {
			return nil, err
		}
	}
	client, err := hysteria2.NewClient(clientOptions)
	if err != nil {
		return nil, err
	}
	return &pinnedOutbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeHysteria2, tag, networkList, options.DialerOptions),
		logger:  logger,
		client:  client,
	}, nil
}

func pinCertificate(config *tls.STDConfig, pin [sha256.Size]byte) {
	// ChromeParrot accepts VerifyPeerCertificate. Require a full handshake
	// because that callback is skipped when resuming a TLS session.
	config.SessionTicketsDisabled = true
	verify := config.VerifyPeerCertificate
	config.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 || sha256.Sum256(rawCerts[0]) != pin {
			return E.New("Hysteria 2 server certificate does not match pinSHA256")
		}
		if verify != nil {
			return verify(rawCerts, verifiedChains)
		}
		return nil
	}
}

func tlsServerAddress(options option.Hysteria2OutboundOptions) (string, error) {
	if options.Realm == nil {
		return options.Server, nil
	}
	if options.Server != "" || options.ServerPort != 0 || len(options.ServerPorts) > 0 {
		return "", E.New("realm conflicts with server, server_port, and server_ports")
	}
	serverURL, err := url.Parse(options.Realm.ServerURL)
	if err != nil {
		return "", E.Cause(err, "parse realm server_url")
	}
	serverName := serverURL.Hostname()
	if serverName == "" {
		return "", E.New("missing host in realm server_url")
	}
	return serverName, nil
}

func newRealmOptions(ctx context.Context, logger log.ContextLogger, options *option.Hysteria2Realm, queryOptions adapter.DNSQueryOptions) (*realm.Options, error) {
	httpTransport, err := service.FromContext[adapter.HTTPClientManager](ctx).ResolveTransport(ctx, logger, common.PtrValueOrDefault(options.HTTPClient))
	if err != nil {
		return nil, E.Cause(err, "create realm http client")
	}
	dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
	result := &realm.Options{
		ServerURL:   options.ServerURL,
		Token:       options.Token,
		RealmID:     options.RealmID,
		STUNServers: options.STUNServers,
		HTTPClient:  &http.Client{Transport: httpTransport},
		Resolver: func(ctx context.Context, host string, ipv4, ipv6 bool) ([]netip.Addr, error) {
			dnsOptions := queryOptions
			switch {
			case ipv4 && !ipv6:
				dnsOptions.Strategy = C.DomainStrategyIPv4Only
			case !ipv4 && ipv6:
				dnsOptions.Strategy = C.DomainStrategyIPv6Only
			}
			return dnsRouter.Lookup(ctx, host, dnsOptions)
		},
		Logger:    logger,
		IPVersion: options.IPVersion,
	}
	if options.PortMapping != nil && options.PortMapping.Enabled {
		result.PortMapping = &realm.PortMappingOptions{
			Timeout:  time.Duration(options.PortMapping.Timeout),
			Lifetime: time.Duration(options.PortMapping.Lifetime),
		}
	}
	return result, nil
}

func (h *pinnedOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.DialConn(ctx, destination)
	case N.NetworkUDP:
		conn, err := h.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(conn, destination), nil
	default:
		return nil, E.New("unsupported network: ", network)
	}
}

func (h *pinnedOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return h.client.ListenPacket(ctx)
}

func (h *pinnedOutbound) InterfaceUpdated(ctx context.Context) {
	h.client.CloseWithError(E.New("network changed"))
}

func (h *pinnedOutbound) MultiplexEnabled() bool {
	return true
}

func (h *pinnedOutbound) SetKeepIdleConnections(keep bool) {
	h.client.SetKeepIdleConnections(keep)
}

func (h *pinnedOutbound) CloseIdleConnections() {
	h.client.CloseIdleConnections()
}

func (h *pinnedOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(func() error {
			return h.client.CloseWithError(os.ErrClosed)
		})
	}
	return nil
}
