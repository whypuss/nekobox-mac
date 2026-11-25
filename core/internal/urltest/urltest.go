// SPDX-License-Identifier: GPL-3.0-or-later
package urltest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	DefaultURL       = "http://cp.cloudflare.com/"
	DefaultTimeoutMs = 5000
)

// PickOutbound selects the proxy outbound to test from a sing-box OutboundManager.
// It prefers the default outbound unless it is missing, direct, or block, in which
// case it falls back to the explicit "proxy" outbound when present.
func PickOutbound(manager adapter.OutboundManager) (adapter.Outbound, error) {
	if manager == nil {
		return nil, errors.New("outbound manager is unavailable")
	}
	out := manager.Default()
	if out == nil || out.Type() == C.TypeDirect || out.Type() == C.TypeBlock {
		if proxy, loaded := manager.Outbound("proxy"); loaded && proxy != nil {
			out = proxy
		}
	}
	if out == nil {
		return nil, errors.New("no proxy outbound available")
	}
	return out, nil
}

// Test measures pure 1-RTT HTTP latency through dialer (or direct net.Dialer if nil)
// in milliseconds (minimum 1ms on success), matching NekoBox's UrlTestStandard_RTT:
//   - For https://, the TLS handshake already completes the full proxy+target tunnel
//     before WroteHeaders fires, so a single HTTP/1.1 request's
//     (GotFirstResponseByte - WroteHeaders) is exact 1-RTT.
//   - For http://, many proxy protocols use lazy/early-data handshakes that run on
//     the first write; we therefore warm the keep-alive tunnel on request #1 and
//     measure (GotFirstResponseByte - WroteHeaders) on a reused request #2, falling
//     back cleanly to request #1 if the server closes keep-alive or budget is tight.
func Test(dialer N.Dialer, link string, timeoutMs int32, rootCAs *x509.CertPool) (int32, error) {
	link = strings.TrimSpace(link)
	if link == "" {
		link = DefaultURL
	}
	parsed, err := url.Parse(link)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return 0, fmt.Errorf("invalid url test target %q", link)
	}
	if timeoutMs <= 0 {
		timeoutMs = DefaultTimeoutMs
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	transport := &http.Transport{
		DisableKeepAlives: false,
		MaxIdleConns:      1,
		MaxIdleConnsPerHost: 1,
		ForceAttemptHTTP2: false,
		TLSNextProto:      make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		TLSClientConfig: &tls.Config{
			RootCAs: rootCAs,
		},
	}
	if dialer != nil {
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
		}
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	isHTTPS := parsed.Scheme == "https"
	rtt1, _, connClosed, err := doProbe(ctx, client, link, isHTTPS)
	if err != nil {
		return 0, err
	}
	if isHTTPS || connClosed {
		return rtt1, nil
	}

	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < 250*time.Millisecond {
		return rtt1, nil
	}

	rtt2, reused, _, err2 := doProbe(ctx, client, link, true)
	if err2 == nil && reused && rtt2 >= 1 {
		return rtt2, nil
	}
	return rtt1, nil
}

func doProbe(ctx context.Context, client *http.Client, link string, closeAfter bool) (int32, bool, bool, error) {
	base := time.Now()
	var wroteHeadersNs atomic.Int64
	var firstByteNs atomic.Int64
	var reusedConn atomic.Bool

	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			reusedConn.Store(info.Reused)
		},
		WroteHeaders: func() {
			wroteHeadersNs.Store(time.Since(base).Nanoseconds())
		},
		GotFirstResponseByte: func() {
			firstByteNs.CompareAndSwap(0, time.Since(base).Nanoseconds())
		},
	}

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, link, nil)
	if err != nil {
		return 0, false, true, err
	}
	if closeAfter {
		req.Header.Set("Connection", "close")
	}

	reqStart := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, reusedConn.Load(), true, err
	}
	// Drain small response bodies (204 / 302 / tiny test pages) so http.Transport
	// can return the underlying tunnel to the idle keep-alive pool.
	_, _ = io.CopyN(io.Discard, resp.Body, 4096)
	_ = resp.Body.Close()

	var elapsedMs int64
	wrote := wroteHeadersNs.Load()
	first := firstByteNs.Load()
	if wrote > 0 && first >= wrote {
		elapsedMs = time.Duration(first - wrote).Milliseconds()
	} else {
		elapsedMs = time.Since(reqStart).Milliseconds()
	}
	if elapsedMs < 1 {
		elapsedMs = 1
	}
	return int32(elapsedMs), reusedConn.Load(), resp.Close, nil
}
