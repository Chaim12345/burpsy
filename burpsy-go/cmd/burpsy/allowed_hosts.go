package main

import (
	"fmt"
	"net"
	"strings"

	"go.uber.org/zap"
)

// parseAllowedHosts reads -web-allowed-host: comma-separated Host values the console answers to on
// top of loopback and its own bind address (burpsy-react-ui-allowed-hosts-flag). The console refuses
// every request whose Host it does not recognise — the DNS-rebinding defence — so a console reached
// by a DNS name has to be told that name. Each entry is a bare name or name:port; anything with a
// scheme, a path, userinfo or a wildcard is refused, because the list is compared against the Host
// header verbatim and a pattern would silently accept nothing or everything.
func parseAllowedHosts(v string) ([]string, error) {
	var out []string
	for _, raw := range strings.Split(v, ",") {
		h := strings.TrimSpace(raw)
		if h == "" {
			continue
		}
		if strings.ContainsAny(h, "/@*?# ") {
			return nil, fmt.Errorf("-web-allowed-host %q: give a host name or host:port, not a URL or pattern", h)
		}
		name := h
		if host, port, err := net.SplitHostPort(h); err == nil {
			if host == "" || port == "" {
				return nil, fmt.Errorf("-web-allowed-host %q: empty host or port", h)
			}
			name = host
		} else if strings.Count(h, ":") > 0 && net.ParseIP(h) == nil {
			return nil, fmt.Errorf("-web-allowed-host %q: %v", h, err)
		}
		if ip := net.ParseIP(name); ip != nil && ip.IsUnspecified() {
			return nil, fmt.Errorf("-web-allowed-host %q: an unspecified address is never a Host a browser sends", h)
		}
		out = append(out, strings.ToLower(h))
	}
	return out, nil
}

// mustAllowedHosts parses the flag or exits: a mistyped allow-list must not start a console that
// refuses the operator's own browser (or, worse, one they believe accepts it).
func mustAllowedHosts(v string, logger *zap.Logger) []string {
	hosts, err := parseAllowedHosts(v)
	if err != nil {
		logger.Fatal("invalid -web-allowed-host", zap.Error(err))
	}
	return hosts
}
