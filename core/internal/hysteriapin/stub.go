//go:build !with_quic

package hysteriapin

import "github.com/sagernet/sing-box/adapter/outbound"

func Register(_ *outbound.Registry) {}
