// SPDX-License-Identifier: GPL-3.0-or-later
package xraybridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	xoutbound "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/infra/conf"
)

const Type = "xray"

type Options struct {
	Outbound json.RawMessage `json:"outbound"`
	option.DialerOptions
}

func Register(registry *outbound.Registry) {
	outbound.Register[Options](registry, Type, newOutbound)
}

// Xray's system DNS and outbound manager are process-wide. Use one dispatcher
// per process and install each profile under its own handler tag.
var (
	nextHandlerID atomic.Uint64
	runtime       = sync.OnceValues(func() (*core.Instance, error) {
		config, err := (&conf.Config{
			LogConfig: &conf.LogConfig{LogLevel: "none"},
		}).Build()
		if err != nil {
			return nil, err
		}
		instance, err := core.New(config)
		if err != nil {
			return nil, err
		}
		if err := instance.Start(); err != nil {
			instance.Close()
			return nil, err
		}
		return instance, nil
	})
)

type xrayOutbound struct {
	outbound.Adapter
	config   *core.OutboundHandlerConfig
	dialers  profileDialers
	mu       sync.Mutex
	started  bool
	instance *core.Instance
}

func newOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options Options) (adapter.Outbound, error) {
	config, err := buildOutbound(options.Outbound, fmt.Sprintf("nekobox-%d", nextHandlerID.Add(1)))
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
	return &xrayOutbound{
		Adapter: outbound.NewAdapterWithDialerOptions(Type, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		config:  config,
		dialers: profileDialers{ip: ipDialer, domain: domainDialer},
	}, nil
}

func ValidateConfig(config string) error {
	var options Options
	if json.Unmarshal([]byte(config), &options) != nil {
		return errors.New("invalid Xray configuration")
	}
	_, err := buildOutbound(options.Outbound, "validate")
	return err
}

func buildOutbound(raw json.RawMessage, tag string) (*core.OutboundHandlerConfig, error) {
	var outboundConfig conf.OutboundDetourConfig
	if len(raw) == 0 {
		return nil, errors.New("Xray outbound is required")
	}
	if err := json.Unmarshal(raw, &outboundConfig); err != nil {
		return nil, fmt.Errorf("decode Xray outbound: %w", err)
	}
	if !supportsProtocol(outboundConfig.Protocol) {
		return nil, fmt.Errorf("unsupported Xray outbound protocol %q", outboundConfig.Protocol)
	}
	if stream := outboundConfig.StreamSetting; stream != nil && stream.SocketSettings != nil &&
		stream.SocketSettings.DialerProxy != "" {
		return nil, errors.New("use the sing-box detour field for an Xray outbound chain")
	}
	outboundConfig.Tag = tag
	config, err := outboundConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("build Xray outbound: %w", err)
	}
	return config, nil
}

func supportsProtocol(protocol string) bool {
	switch strings.ToLower(protocol) {
	case "vless", "vmess", "trojan", "shadowsocks", "socks", "http", "wireguard", "hysteria", "masque":
		return true
	default:
		return false
	}
}

func (o *xrayOutbound) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.started = true
	return nil
}

func (o *xrayOutbound) activeInstance() (*core.Instance, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.started {
		return nil, net.ErrClosed
	}
	if o.instance != nil {
		return o.instance, nil
	}
	instance, err := runtime()
	if err != nil {
		return nil, err
	}
	if err := core.AddOutboundHandler(instance, o.config); err != nil {
		return nil, errors.Join(err, removeHandler(instance, o.config.Tag))
	}
	o.instance = instance
	return instance, nil
}

func (o *xrayOutbound) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.started = false
	instance := o.instance
	o.instance = nil
	if instance == nil {
		return nil
	}
	return removeHandler(instance, o.config.Tag)
}

func removeHandler(instance *core.Instance, tag string) error {
	manager := instance.GetFeature(xoutbound.ManagerType()).(xoutbound.Manager)
	handler := manager.GetHandler(tag)
	if handler == nil {
		return nil
	}
	return errors.Join(manager.RemoveHandler(context.Background(), tag), handler.Close())
}

func (o *xrayOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	address := xnet.ParseAddress(destination.AddrString())
	port := xnet.Port(destination.Port)
	var target xnet.Destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		target = xnet.TCPDestination(address, port)
	case N.NetworkUDP:
		target = xnet.UDPDestination(address, port)
	default:
		return nil, fmt.Errorf("unsupported Xray network %q", network)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	instance, err := o.activeInstance()
	if err != nil {
		return nil, err
	}
	ctx = session.SetForcedOutboundTagToContext(ctx, o.config.Tag)
	ctx = context.WithValue(ctx, dialersKey{}, o.dialers)
	return core.Dial(ctx, instance, target)
}

func (o *xrayOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := o.DialContext(ctx, N.NetworkUDP, destination)
	if err != nil {
		return nil, err
	}
	return &connectedPacketConn{Conn: conn, destination: destination}, nil
}

// Xray's connected UDP stream retains the destination's hostname for XUDP.
// It also provides deadlines through net.Conn.
type connectedPacketConn struct {
	net.Conn
	destination net.Addr
}

func (c *connectedPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(buffer)
	return n, c.destination, err
}

func (c *connectedPacketConn) WriteTo(buffer []byte, address net.Addr) (int, error) {
	if address == nil || address.String() != c.destination.String() {
		return 0, errors.New("UDP destination differs from the connected Xray stream")
	}
	return c.Conn.Write(buffer)
}
