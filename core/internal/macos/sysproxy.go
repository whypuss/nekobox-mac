// SPDX-License-Identifier: GPL-3.0-or-later
//go:build darwin

package macos

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

var defaultBypassDomains = []string{
	"127.0.0.1",
	"localhost",
	"*.local",
	"169.254.0.0/16",
	"192.168.0.0/16",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"100.64.0.0/10",
	"::1",
	"fe80::/10",
	"*.cn",
}

// ActiveNetworkServices returns enabled macOS network services (e.g. Wi-Fi, Ethernet).
func ActiveNetworkServices() ([]string, error) {
	out, err := exec.Command("/usr/sbin/networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, fmt.Errorf("list network services: %w", err)
	}
	lines := strings.Split(string(out), "\n")
	var services []string
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "An asterisk") || strings.HasPrefix(line, "*") {
			continue
		}
		// Skip virtual tunnel/bridge/bluetooth services that are not primary internet interfaces
		lower := strings.ToLower(line)
		if strings.Contains(lower, "bluetooth") || strings.Contains(lower, "thunderbolt bridge") {
			continue
		}
		services = append(services, line)
	}
	return services, nil
}

// EnableSystemProxy configures HTTP, HTTPS, and SOCKS5 proxies on active macOS network services.
func EnableSystemProxy(host string, port int) ([]string, error) {
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	services, err := ActiveNetworkServices()
	if err != nil {
		return nil, err
	}
	portStr := strconv.Itoa(port)
	var applied []string
	var lastErr error
	for _, svc := range services {
		cmds := [][]string{
			{"-setwebproxy", svc, host, portStr},
			{"-setsecurewebproxy", svc, host, portStr},
			{"-setsocksfirewallproxy", svc, host, portStr},
			{"-setwebproxystate", svc, "on"},
			{"-setsecurewebproxystate", svc, "on"},
			{"-setsocksfirewallproxystate", svc, "on"},
		}
		ok := true
		for _, args := range cmds {
			if err := exec.Command("/usr/sbin/networksetup", args...).Run(); err != nil {
				lastErr = err
				ok = false
				break
			}
		}
		if ok {
			bypassArgs := append([]string{"-setproxybypassdomains", svc}, defaultBypassDomains...)
			_ = exec.Command("/usr/sbin/networksetup", bypassArgs...).Run()
			applied = append(applied, svc)
		}
	}
	if len(applied) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return applied, nil
}

// DisableSystemProxy turns off HTTP, HTTPS, and SOCKS5 system proxies on active macOS services.
func DisableSystemProxy() error {
	services, err := ActiveNetworkServices()
	if err != nil {
		return err
	}
	var lastErr error
	for _, svc := range services {
		for _, flag := range []string{"-setwebproxystate", "-setsecurewebproxystate", "-setsocksfirewallproxystate"} {
			if err := exec.Command("/usr/sbin/networksetup", flag, svc, "off").Run(); err != nil {
				lastErr = err
			}
		}
	}
	return lastErr
}

// SystemProxyStatus reports whether macOS system proxy is currently enabled on any service.
type SystemProxyStatus struct {
	Enabled  bool     `json:"enabled"`
	Host     string   `json:"host,omitempty"`
	Port     int      `json:"port,omitempty"`
	Services []string `json:"services,omitempty"`
}

func GetSystemProxyStatus() SystemProxyStatus {
	services, err := ActiveNetworkServices()
	if err != nil {
		return SystemProxyStatus{}
	}
	st := SystemProxyStatus{}
	for _, svc := range services {
		out, err := exec.Command("/usr/sbin/networksetup", "-getwebproxy", svc).Output()
		if err != nil {
			continue
		}
		text := string(out)
		if strings.Contains(text, "Enabled: Yes") {
			st.Enabled = true
			st.Services = append(st.Services, svc)
			for _, line := range strings.Split(text, "\n") {
				if strings.HasPrefix(line, "Server:") {
					st.Host = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
				} else if strings.HasPrefix(line, "Port:") {
					st.Port, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Port:")))
				}
			}
		}
	}
	return st
}
