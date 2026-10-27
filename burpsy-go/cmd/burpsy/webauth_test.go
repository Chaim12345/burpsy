package main

import (
	"strings"
	"testing"
)

func TestANonLoopbackWebBindNeedsATokenToStart(t *testing.T) {
	for _, bind := range []string{"0.0.0.0:8081", ":8081", "[::]:8081", "10.0.0.5:8081", "example.com:8081", "192.168.1.9:80", "not-an-address"} {
		if err := webExposureError(bind, "", nil); err == nil {
			t.Errorf("bind %q with no token started; the console would be open on the network", bind)
		} else if strings.Contains(err.Error(), "0123456789") {
			t.Errorf("error echoes a token-like value: %v", err)
		}
		if err := webExposureError(bind, "0123456789abcdef", nil); err != nil {
			t.Errorf("bind %q with a token was refused: %v", bind, err)
		}
	}
}

func TestALoopbackBindStartsWithNoTokenExactlyAsBefore(t *testing.T) {
	for _, bind := range []string{"127.0.0.1:8081", "localhost:8081", "[::1]:8081", "127.0.0.2:9"} {
		if err := webExposureError(bind, "", nil); err != nil {
			t.Errorf("loopback bind %q refused: %v", bind, err)
		}
	}
}

func TestNamingAHostWithoutATokenIsRefused(t *testing.T) {
	if err := webExposureError("127.0.0.1:8081", "", []string{"burpsy.example.com"}); err == nil {
		t.Fatal("-allow-host with no token was accepted")
	}
	if err := webExposureError("0.0.0.0:8081", "0123456789abcdef", []string{"burpsy.example.com"}); err != nil {
		t.Fatalf("token plus allowed host refused: %v", err)
	}
}

func TestParseAllowHosts(t *testing.T) {
	got := parseAllowHosts(" a.example.com , ,b.example.com:8443,")
	if len(got) != 2 || got[0] != "a.example.com" || got[1] != "b.example.com:8443" {
		t.Fatalf("parseAllowHosts = %q", got)
	}
	if len(parseAllowHosts("")) != 0 {
		t.Fatal("empty flag produced hosts")
	}
}

func TestTheTokenIsRemovedFromTheEnvironmentOnceRead(t *testing.T) {
	t.Setenv(authTokenEnv, "0123456789abcdef")
	if takeAuthToken() != "0123456789abcdef" {
		t.Fatal("token not read")
	}
	if takeAuthToken() != "" {
		t.Fatal("token still in the environment after it was taken; child tools would inherit it")
	}
}
