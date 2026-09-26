package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/scanner"
)

// burpsy-react-ui-86le: skip_all_tests_for_parameters was reported by the config-key table as
// `applies: false` while the engine HONOURED the control under a Go-API field name. This table is
// what an operator — or a preset importer reading the matrix — is told about burpsy's support, so a
// false "not applied" here is a false statement about the product rather than a stale note.

type configKeyWire struct {
	Name    string `json:"name"`
	BurpKey string `json:"burp_key"`
	What    string `json:"what"`
	Applies bool   `json:"applies"`
	Partial bool   `json:"partial"`
}

func scannerConfigKeys(t *testing.T, s *Server) []configKeyWire {
	t.Helper()
	rec := get(t, s, "/api/scanner/configs")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/scanner/configs: %d", rec.Code)
	}
	var body struct {
		Keys []struct {
			Keys []configKeyWire `json:"keys"`
		} `json:"configs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Keys) == 0 {
		t.Fatal("no configuration reported any keys; the whole-set endpoint is what an operator reads")
	}
	return body.Keys[0].Keys
}

// The skip list is honoured by the engine and must not be reported as unsupported on the wire.
func TestTheSkipListKeyIsNotReportedAsUnsupportedOnTheWire(t *testing.T) {
	s := newTestServer()
	for _, k := range scannerConfigKeys(t, s) {
		if k.Name != "skip_all_tests_for_parameters" {
			continue
		}
		if !k.Applies {
			t.Errorf("the wire says skip_all_tests_for_parameters does not apply, while " +
				"PUT /api/scanner/config accepts skip_all_tests_for_parameters and the enumerator " +
				"honours it (burpsy-react-ui-86le)")
		}
		if !k.Partial {
			t.Errorf("the wire does not mark the key partial, so a console filtering on Partial to " +
				"exclude reduced-support controls from \"unsupported\" cannot")
		}
		if len(k.What) == 0 {
			t.Error("the row has no description; a partial row is where the operator reads what is " +
				"missing, and an empty one leaves the third state unexplained")
		}
		return
	}
	t.Fatal("no skip_all_tests_for_parameters on the wire at all; the key is missing from the " +
		"disclosure rather than misdescribed, which is the same defect wearing a different hat")
}

// Every key field must appear on the wire UNDER ITS OWN NAME, in the shape a TypeScript consumer
// declares. Go marshals an untagged field under its Go name, so a lost `json:"..."` tag is a
// renamed field and not a compile error: it happened here, and the struct-level tests could not
// see it because they read the Go value. This decodes the response and checks the KEYS themselves.
func TestEveryConfigKeyFieldReachesTheWireUnderItsOwnName(t *testing.T) {
	s := newTestServer()
	rec := get(t, s, "/api/scanner/configs")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/scanner/configs: %d", rec.Code)
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	configs, _ := raw["configs"].([]any)
	if len(configs) == 0 {
		t.Skip("no shipped configuration to read a key from")
	}
	first, _ := configs[0].(map[string]any)
	keys, _ := first["keys"].([]any)
	if len(keys) == 0 {
		t.Fatal("a configuration reported no keys")
	}
	row, _ := keys[0].(map[string]any)
	for _, want := range []string{"name", "burp_key", "what", "set", "applies", "partial"} {
		if _, present := row[want]; !present {
			t.Errorf("the wire carries no %q field; Go marshals an untagged field under its Go name, so "+
				"a lost tag renames the field rather than failing to compile (the keys present: %v)",
				want, configKeyFieldNames(row))
		}
	}
}

func configKeyFieldNames(row map[string]any) []string {
	out := make([]string, 0, len(row))
	for k := range row {
		out = append(out, k)
	}
	return out
}

// And the control the row names is the one the endpoint that sets it writes into the run config.
func TestTheKeyTheRowNamesIsTheOneTheConfigEndpointAccepts(t *testing.T) {
	// The endpoint that APPLIES the control. If this stopped accepting the key, the row's "applies"
	// would become a new lie in the other direction, and nothing else here would notice.
	cfg, err := applyConfigOverlay(t, scanner.AuditConfig{}, `{"skip_all_tests_for_parameters":["user","token"]}`)
	if err != nil {
		t.Fatalf("the endpoint that sets the control refused it: %v", err)
	}
	if len(cfg.SkipAllTestsForParameters) != 2 {
		t.Errorf("the endpoint set %v, want the two names it was given; the row claims this control "+
			"applies and this is where that claim is cashed", cfg.SkipAllTestsForParameters)
	}
}
