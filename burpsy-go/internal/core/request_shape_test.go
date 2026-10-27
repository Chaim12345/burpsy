package core

import "testing"

func shapeFP(t *testing.T, raw string) uint64 {
	t.Helper()
	fp := RequestShapeFingerprint([]byte(raw))
	if fp == 0 {
		t.Fatal("shape fingerprint of a real request is zero")
	}
	return fp
}

func TestRequestShapeFingerprintMasksOnlyTheVolatileRegions(t *testing.T) {
	base := "POST /login?next=/dash&csrf=AAA HTTP/1.1\r\nHost: h.test\r\nCookie: sid=111; theme=dark\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=kim&csrf=AAA"
	same := "POST /login?next=/dash&csrf=BBB HTTP/1.1\r\nHost: h.test\r\nCookie: sid=222; theme=dark\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=kim&csrf=BBB"
	if shapeFP(t, base) != shapeFP(t, same) {
		t.Error("differing only in CSRF values (query+body) and the session cookie value must be one shape")
	}
	if RequestFingerprint([]byte(base)) == RequestFingerprint([]byte(same)) {
		t.Error("the raw fingerprint must still tell those two captures apart")
	}

	otherParam := "POST /login?next=/other&csrf=AAA HTTP/1.1\r\nHost: h.test\r\nCookie: sid=111; theme=dark\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=kim&csrf=AAA"
	if shapeFP(t, base) == shapeFP(t, otherParam) {
		t.Error("a changed non-volatile parameter value is a changed shape and must re-audit")
	}
	otherBody := "POST /login?next=/dash&csrf=AAA HTTP/1.1\r\nHost: h.test\r\nCookie: sid=111; theme=dark\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=sam&csrf=AAA"
	if shapeFP(t, base) == shapeFP(t, otherBody) {
		t.Error("a changed non-volatile body field is a changed shape and must re-audit")
	}
	otherCookieName := "POST /login?next=/dash&csrf=AAA HTTP/1.1\r\nHost: h.test\r\nCookie: sid=111; prefs=x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=kim&csrf=AAA"
	if shapeFP(t, base) == shapeFP(t, otherCookieName) {
		t.Error("a different cookie NAME set is a different shape; only the values are masked")
	}
	jsonBody := "POST /login?next=/dash&csrf=AAA HTTP/1.1\r\nHost: h.test\r\nContent-Type: application/json\r\n\r\n{\"user\":\"kim\",\"ts\":\"1\"}"
	jsonBody2 := "POST /login?next=/dash&csrf=AAA HTTP/1.1\r\nHost: h.test\r\nContent-Type: application/json\r\n\r\n{\"user\":\"kim\",\"ts\":\"2\"}"
	if shapeFP(t, jsonBody) == shapeFP(t, jsonBody2) {
		t.Error("JSON bodies are not parsed (documented): a changed JSON field is a changed shape; the run's variant cap bounds that case")
	}
	if RequestShapeFingerprint(nil) != 0 {
		t.Error("no request bytes fingerprints to zero, matching RequestFingerprint")
	}
}
