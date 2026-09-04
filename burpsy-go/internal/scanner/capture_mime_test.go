package scanner

// The row's Mime describes the response it indexes.
//
// This is the seam the History MIME column and type filter actually depend on: Capture.Record is
// where nearly all proxy traffic becomes an exchange, so a row minted here with an empty Mime is a
// blank cell in the UI no matter how correct core.MimeEssence is on its own. Testing the extractor
// alone would not have caught the original defect either — there was nothing wrong with reading a
// Content-Type header, the field simply was never set.

import (
	"testing"
)

func TestTheRowCarriesTheResponseMediaType(t *testing.T) {
	ex, _ := recordResponse(t, "HTTP/1.1 200 OK\r\nContent-Type: text/HTML; charset=utf-8\r\n\r\n<html>")
	if ex.Mime != "text/html" {
		t.Errorf("Mime = %q, want %q — the parameters must be stripped and the type folded to lower case",
			ex.Mime, "text/html")
	}
}

// A response that names no type leaves Mime empty, and the row is still a complete exchange. The
// distinction from "no response" is carried by Response, which Record always sets — it refuses a
// capture with no response bytes outright (see capture_test.go), so a row from this producer can never
// be the response-less shape.
func TestARowWhoseResponseNamedNoTypeIsEmptyButComplete(t *testing.T) {
	ex, _ := recordResponse(t, "HTTP/1.1 204 No Content\r\nServer: nginx\r\n\r\n")
	if ex.Mime != "" {
		t.Errorf("Mime = %q, want the empty string", ex.Mime)
	}
	if ex.Response == nil {
		t.Fatal("Record produced a row with no response, which it is supposed to refuse outright")
	}
	// This is what lets the UI say "untyped" here and "—" on a blind tunnel: same Mime, different
	// Response. If Record ever started minting response-less rows the two would become one blank cell
	// again, so the assertion above is load-bearing rather than decorative.
}

// A JSON API response, the case an operator filters on most, end to end through the producer.
func TestTheRowCarriesAJSONMediaType(t *testing.T) {
	ex, _ := recordResponse(t, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
	if ex.Mime != "application/json" {
		t.Errorf("Mime = %q, want %q", ex.Mime, "application/json")
	}
}
