package proxy

import "testing"

func TestParseStatusCodeReadsThreeDigitCode(t *testing.T) {
	raw := []byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
	st := parseStatusCode(raw)
	if st == nil {
		t.Fatal("parseStatusCode returned nil for a well-formed response")
	}
	if *st != 404 {
		t.Errorf("status = %d, want 404", *st)
	}
}

func TestParseStatusCodeHandlesLFStyleLineEndings(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\nServer: x\n\nbody")
	st := parseStatusCode(raw)
	if st == nil || *st != 200 {
		t.Errorf("status = %v, want 200", st)
	}
}

// An unparseable first line yields nil, so absent status is honest (never guessed).
func TestParseStatusCodeReturnsNilForGarbage(t *testing.T) {
	if st := parseStatusCode([]byte("not a response")); st != nil {
		t.Errorf("garbage status = %v, want nil", st)
	}
	if st := parseStatusCode([]byte("")); st != nil {
		t.Errorf("empty status = %v, want nil", st)
	}
	if st := parseStatusCode([]byte("HTTP/1.1 99 BAD\r\n\r\n")); st != nil {
		t.Errorf("out-of-range status = %v, want nil", st)
	}
}
