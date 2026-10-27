package main

import (
	"reflect"
	"testing"
)

func TestWebAllowedHostReadsNamesAndNamePorts(t *testing.T) {
	got, err := parseAllowedHosts(" burp.internal , Console.Lab:8081,,10.0.0.5:8081 ")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"burp.internal", "console.lab:8081", "10.0.0.5:8081"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if got, err := parseAllowedHosts(""); err != nil || len(got) != 0 {
		t.Errorf("empty flag = %q, %v; want nothing", got, err)
	}
}

func TestWebAllowedHostRefusesURLsPatternsAndWildcards(t *testing.T) {
	for _, bad := range []string{"http://burp.internal", "burp.internal/", "*.lab", "u@burp.internal",
		"burp.internal:", ":8081", "0.0.0.0:8081", "[::]:8081", "a b"} {
		if got, err := parseAllowedHosts(bad); err == nil {
			t.Errorf("%q was accepted as %q", bad, got)
		}
	}
}
