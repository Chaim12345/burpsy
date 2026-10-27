package main

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// authTokenEnv names the environment variable that carries the console token. An environment variable
// and not a flag, so the token never appears in the process list or a shell history. main reads it once
// and removes it from the environment, so a tool the engine starts (-tools, extscan, plugins) does not
// inherit it.
const authTokenEnv = "BURPSY_AUTH_TOKEN"

// takeAuthToken returns the console token from the environment and unsets it.
func takeAuthToken() string {
	t := os.Getenv(authTokenEnv)
	if t != "" {
		_ = os.Unsetenv(authTokenEnv)
	}
	return t
}

// parseAllowHosts splits the -allow-host flag into Host values, dropping blanks.
func parseAllowHosts(v string) []string {
	var out []string
	for _, h := range strings.Split(v, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// webBindIsLoopback reports whether the web bind address is reachable only from this machine. An empty
// host (":8081") and a wildcard both listen on every interface, so they are not loopback. A host name
// other than "localhost" is not loopback either: it can resolve anywhere.
func webBindIsLoopback(bind string) bool {
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// webExposureError refuses a web bind that would put the console on the network without a credential,
// and an allowed-host list with no credential. It runs before anything listens, so a misconfigured
// deployment exits at start rather than serving an open console.
//
// A loopback bind with no token is the unchanged default and passes. A token with a loopback bind is
// allowed too (a reverse proxy on the same machine).
func webExposureError(bind, token string, allowHosts []string) error {
	if token == "" {
		if !webBindIsLoopback(bind) {
			return fmt.Errorf("-web %q is not loopback: set %s (at least 16 characters) so the console has a credential, "+
				"or bind to 127.0.0.1", bind, authTokenEnv)
		}
		if len(allowHosts) > 0 {
			return fmt.Errorf("-allow-host needs %s: naming a Host without a credential would open every mutating route", authTokenEnv)
		}
	}
	return nil
}
