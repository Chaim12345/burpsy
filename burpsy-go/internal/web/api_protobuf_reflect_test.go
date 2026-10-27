package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/grpcproto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// 47id: the reflection fetch is per-request opt-in behind the scope gate, its
// provenance is marked, and a failed fetch still shows the schemaless tree. The
// zero-dial assertions are load-bearing (integrator ruling 8).

// reflectFixture is an in-process gRPC server reflecting a service whose schema
// the test registers globally (unique package: the registry has no unregister).
const reflectFixtureProto = `syntax = "proto3";
package reflectapi;
message Sighting { int64 seen_at = 1; string where = 2; }
service Sightings { rpc List (Sighting) returns (Sighting); }
`

func startReflectFixture(t *testing.T, serveReflection bool) (dialTo func(target string, useTLS bool) (*grpc.ClientConn, error), dials *atomic.Int64) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	if serveReflection {
		srv.RegisterService(&grpc.ServiceDesc{
			ServiceName: "reflectapi.Sightings",
			Metadata:    "reflectapi/sightings.proto",
		}, nil)
		reflection.Register(srv)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	dials = &atomic.Int64{}
	return func(target string, useTLS bool) (*grpc.ClientConn, error) {
		dials.Add(1)
		return grpc.NewClient("passthrough:///bufconn",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
	}, dials
}

func registerReflectFixtureSchema(t *testing.T) {
	t.Helper()
	files, err := grpcproto.CompileProto(reflectFixtureProto, "reflectapi/sightings.proto")
	if err != nil {
		t.Fatalf("compile fixture: %v", err)
	}
	if err := protoregistry.GlobalFiles.RegisterFile(files); err != nil {
		t.Fatalf("register: %v", err)
	}
}

func withReflectDial(t *testing.T, dial func(string, bool) (*grpc.ClientConn, error)) {
	t.Helper()
	old := protobufReflectDial
	protobufReflectDial = dial
	t.Cleanup(func() { protobufReflectDial = old })
}

// field 1 varint 42, field 2 LEN "haifa"
var reflectSampleBody = []byte{0x08, 0x2a, 0x12, 0x05, 'h', 'a', 'i', 'f', 'a'}

func TestReflectDecodeNamesFieldsFromTheTargetSchema(t *testing.T) {
	registerReflectFixtureSchema(t)
	dial, dials := startReflectFixture(t, true)
	withReflectDial(t, dial)
	s := NewServer(core.NewTrafficStore(), core.NewScope())

	r := postJSON(t, s, "/api/protobuf/reflect-decode", map[string]any{
		"body_base64": base64.StdEncoding.EncodeToString(reflectSampleBody),
		"reflect":     map[string]any{"target": "target.test:443", "service": "reflectapi.Sightings", "tls": true},
	})
	if r.Code != http.StatusOK {
		t.Fatalf("decode = %d: %s", r.Code, r.Body.String())
	}
	var resp protoDecodeResponse
	if err := json.Unmarshal(r.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	f := resp.Frames[0].Fields
	if len(f) != 2 || f[0].Name != "seen_at" || f[1].Name != "where" {
		t.Fatalf("fields not named from the reflected schema: %+v", f)
	}
	if resp.SchemaSource != "reflection" {
		t.Fatalf("the names' provenance must read as target-served: %q", resp.SchemaSource)
	}
	if len(resp.SchemaFiles) == 0 || resp.SchemaFiles[0] != "reflectapi/sightings.proto" {
		t.Fatalf("the fetched files must be listed: %v", resp.SchemaFiles)
	}
	if dials.Load() != 1 {
		t.Fatalf("exactly one fetch per request, got %d", dials.Load())
	}
}

func TestReflectDecodeRefusesAnOutOfScopeTargetWithoutDialing(t *testing.T) {
	dial, dials := startReflectFixture(t, true)
	withReflectDial(t, dial)
	scope := core.NewScope()
	scope.AddInclude("scoped-target.test")
	scope.SetDropOutOfScope(true)
	s := NewServer(core.NewTrafficStore(), scope)

	r := postJSON(t, s, "/api/protobuf/reflect-decode", map[string]any{
		"body_base64": base64.StdEncoding.EncodeToString(reflectSampleBody),
		"reflect":     map[string]any{"target": "other.test:443", "service": "reflectapi.Sightings", "tls": true},
	})
	if r.Code != http.StatusForbidden {
		t.Fatalf("out-of-scope must refuse, got %d: %s", r.Code, r.Body.String())
	}
	if !strings.Contains(r.Body.String(), "scope") {
		t.Fatalf("the refusal names scope: %q", r.Body.String())
	}
	if dials.Load() != 0 {
		t.Fatalf("LOAD-BEARING: a refused target was dialed %d time(s)", dials.Load())
	}
}

func TestReflectDecodeAMissingReflectionServesTheSchemalessTreeHonestly(t *testing.T) {
	dial, _ := startReflectFixture(t, false) // no reflection on the server
	withReflectDial(t, dial)
	s := NewServer(core.NewTrafficStore(), core.NewScope())

	r := postJSON(t, s, "/api/protobuf/reflect-decode", map[string]any{
		"body_base64": base64.StdEncoding.EncodeToString(reflectSampleBody),
		"reflect":     map[string]any{"target": "target.test:80", "service": "reflectapi.Sightings", "tls": false},
	})
	if r.Code != http.StatusOK {
		t.Fatalf("a failed fetch is reported, not a 4xx: got %d", r.Code)
	}
	var resp protoDecodeResponse
	_ = json.Unmarshal(r.Body.Bytes(), &resp)
	fr := resp.Frames[0]
	if !strings.Contains(fr.Error, "reflection") {
		t.Fatalf("the failed fetch must be named: %+v", fr)
	}
	if len(fr.Fields) != 2 || fr.Fields[0].Name != "" {
		t.Fatalf("the schemaless tree stays, making no claims: %+v", fr.Fields)
	}
	if resp.SchemaSource != "" {
		t.Fatalf("no schema, no provenance mark: %q", resp.SchemaSource)
	}
}

func TestReflectDecodeNeverGuessesATarget(t *testing.T) {
	dial, dials := startReflectFixture(t, true)
	withReflectDial(t, dial)
	s := NewServer(core.NewTrafficStore(), core.NewScope())
	for name, reflect := range map[string]map[string]any{
		"no target":  {"service": "reflectapi.Sightings"},
		"no service": {"target": "target.test:443"},
	} {
		r := postJSON(t, s, "/api/protobuf/reflect-decode", map[string]any{
			"body_base64": base64.StdEncoding.EncodeToString(reflectSampleBody),
			"reflect":     reflect,
		})
		if r.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", name, r.Code)
		}
	}
	if dials.Load() != 0 {
		t.Fatalf("LOAD-BEARING: an invalid request was dialed %d time(s)", dials.Load())
	}
}
