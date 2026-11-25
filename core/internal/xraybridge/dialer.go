// SPDX-License-Identifier: GPL-3.0-or-later
package xraybridge

import (
	"context"
	"net"
	"syscall"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

type dialersKey struct{}

type profileDialers struct {
	ip     N.Dialer
	domain N.Dialer
}

// Install is called during process initialization, before creating any Xray
// handlers. The fallback also protects sockets opened from a background context.
func Install(protect func(int) error) error {
	if protect != nil {
		err := internet.RegisterDialerController(func(_, _ string, raw syscall.RawConn) error {
			var protectErr error
			if err := raw.Control(func(fd uintptr) { protectErr = protect(int(fd)) }); err != nil {
				return err
			}
			return protectErr
		})
		if err != nil {
			return err
		}
	}
	internet.UseAlternativeSystemDialer(&systemDialer{})
	return nil
}

type systemDialer struct {
	internet.DefaultSystemDialer
}

func (d *systemDialer) Dial(ctx context.Context, source xnet.Address, target xnet.Destination, options *internet.SocketConfig) (net.Conn, error) {
	profile, ok := ctx.Value(dialersKey{}).(profileDialers)
	if !ok || (target.Network != xnet.Network_TCP && target.Network != xnet.Network_UDP) {
		return d.DefaultSystemDialer.Dial(ctx, source, target, options)
	}
	destination := M.ParseSocksaddrHostPort(target.Address.String(), uint16(target.Port))
	dialer := profile.ip
	if destination.IsFqdn() {
		dialer = profile.domain
	}
	if target.Network == xnet.Network_TCP {
		return dialer.DialContext(ctx, N.NetworkTCP, destination)
	}
	conn, err := dialer.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	var addr net.Addr = destination
	if destination.IsIP() {
		addr = destination.UDPAddr()
	}
	return &xnet.PacketConnWrapper{PacketConn: conn, Dest: addr}, nil
}
