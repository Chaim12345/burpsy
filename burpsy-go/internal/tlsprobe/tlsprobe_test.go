package tlsprobe

import (
	"context"
	"testing"
)

const selfSignedRecord = `{"host":"self-signed.badssl.com","ip":"104.154.89.105","port":"443","probe_status":true,"tls_version":"tls12","cipher":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","self_signed":true,"not_before":"2026-08-11T21:00:26Z","not_after":"2028-08-10T21:00:26Z","subject_cn":"*.badssl.com","issuer_cn":"*.badssl.com","serial":"A4:54:84:D4:9B:F2:55:4D"}`

const weakCipherRecord = `{"host":"tls-v1-0.badssl.com","port":"1010","probe_status":true,"tls_version":"tls10","cipher_enum":[{"version":"tls10","ciphers":{"weak":["AES128-SHA","ECDHE-RSA-AES256-SHA"],"insecure":["RC4-MD5"]}}]}`

func TestParsesCertificateDefectFlags(t *testing.T) {
	hosts, err := parseJSONL([]byte(selfSignedRecord))
	if err != nil {
		t.Fatalf("parseJSONL: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("parsed %d hosts, want 1", len(hosts))
	}
	h := hosts[0]
	if !h.SelfSigned {
		t.Error("self_signed was not decoded; it is a discriminator for the TLS certificate row")
	}
	if !h.HasCertificateDefect() {
		t.Error("HasCertificateDefect() = false for a self-signed certificate")
	}
	if h.Expired || h.Mismatched || h.Untrusted || h.Revoked {
		t.Errorf("decoded spurious defects: %+v", h)
	}
}

func TestWeakCiphersAreLabelledWithTheirTLSVersion(t *testing.T) {
	hosts, err := parseJSONL([]byte(weakCipherRecord))
	if err != nil {
		t.Fatalf("parseJSONL: %v", err)
	}
	got := hosts[0].WeakCiphers()
	if len(got) != 3 {
		t.Fatalf("WeakCiphers() = %v, want 3 entries (2 weak + 1 insecure)", got)
	}
	for _, c := range got {
		if len(c) < 6 || c[:6] != "tls10:" {
			t.Errorf("cipher %q lost its version prefix; a suite is only weak relative to a version", c)
		}
	}
}

func TestDeprecatedProtocolsReportsSubTLS12Only(t *testing.T) {
	hosts, _ := parseJSONL([]byte(weakCipherRecord))
	if got := hosts[0].DeprecatedProtocols(); len(got) != 1 || got[0] != "tls10" {
		t.Fatalf("DeprecatedProtocols() = %v, want [tls10]", got)
	}
}

func TestNoDefectsOnACleanRecord(t *testing.T) {
	hosts, err := parseJSONL([]byte(`{"host":"example.com","port":"443","probe_status":true,"tls_version":"tls13"}`))
	if err != nil {
		t.Fatalf("parseJSONL: %v", err)
	}
	if hosts[0].HasCertificateDefect() {
		t.Error("a clean record reported a certificate defect")
	}
}

func TestGarbageLinesAreSkippedNotTreatedAsHosts(t *testing.T) {
	in := "[INF] banner text\n\n" + selfSignedRecord + "\n[WRN] warning\n"
	hosts, err := parseJSONL([]byte(in))
	if err != nil {
		t.Fatalf("parseJSONL: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("parsed %d hosts from output with banners, want 1", len(hosts))
	}
}

func TestUnparseableRecordIsAnErrorNotASilentSkip(t *testing.T) {
	if _, err := parseJSONL([]byte(`{"host":"x","expired":"not-a-bool"}`)); err == nil {
		t.Fatal("a malformed record parsed cleanly; unreadable output must not read as no findings")
	}
}

// An empty target list must not look like a completed clean scan.
func TestNoTargetsIsNotInvokedRatherThanCompleted(t *testing.T) {
	res := Probe(context.Background(), nil, Options{})
	if res.Outcome != OutcomeNotInvoked {
		t.Fatalf("Outcome = %v, want OutcomeNotInvoked", res.Outcome)
	}
	if res.Err == nil {
		t.Error("OutcomeNotInvoked carried no explanation")
	}
}

func TestMissingBinaryIsUnavailableRatherThanCompleted(t *testing.T) {
	res := Probe(context.Background(), []string{"example.com"},
		Options{Binary: "tlsx-does-not-exist-9f2a"})
	if res.Outcome != OutcomeUnavailable {
		t.Fatalf("Outcome = %v, want OutcomeUnavailable", res.Outcome)
	}
	if len(res.Hosts) != 0 {
		t.Error("an unavailable tool returned hosts")
	}
}

func TestCipherEnumerationGetsALongerDefaultTimeout(t *testing.T) {
	if (Options{}).timeout() >= (Options{EnumerateCiphers: true}).timeout() {
		t.Error("cipher enumeration must default to a longer timeout than a plain probe")
	}
}
