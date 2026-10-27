package persist

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/burpsy-go/burpsy/internal/netauth"
	"github.com/burpsy-go/burpsy/internal/organizer"
	"go.uber.org/zap"
)

// Four Save/Load pairs no test named (burpsy-react-ui-startup-restore-test): each is saved, the file
// is closed and reopened — what a restart does — and the value must come back as saved, not as the
// first-run default. A setting that silently reverts on restart is how TLS pass-through starts
// intercepting a host the operator excluded.
func TestSettingsWithNoTestSurviveAReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.db")
	s, err := Open(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	creds := []netauth.CredentialRow{
		{Host: "intranet.lab", Scheme: "ntlm", Username: "CORP\\alice", Password: "pw1", Realm: ""},
		{Host: "*.api.lab", Scheme: "basic", Username: "bob", Password: "pw2", Realm: "api"},
	}
	s.SavePlatformAuth(creds)
	s.SavePlatformAuthPrompt(true)
	s.SaveTlsPassthroughMode(true, true)
	identities := []byte(`[{"label":"low","headers":{"Cookie":"s=1"}}]`)
	if err := s.SaveAuthzIdentities(identities); err != nil {
		t.Fatal(err)
	}
	cols := []organizer.Collection{{ID: 1, Name: "IDOR", Note: "check later"}, {ID: 4, Name: "Auth"}}
	s.SaveOrganizerCollections(cols)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	r, err := Open(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got, err := r.LoadPlatformAuth(); err != nil || !reflect.DeepEqual(got, creds) {
		t.Errorf("platform auth after reopen = %+v, %v; want %+v", got, err, creds)
	}
	if !r.LoadPlatformAuthPrompt() {
		t.Error("the platform-auth prompt switch reverted on reopen")
	}
	if a, b := r.LoadTlsPassthroughMode(); !a || !b {
		t.Errorf("TLS pass-through mode after reopen = (%v, %v), want (true, true)", a, b)
	}
	if got, err := r.LoadAuthzIdentities(); err != nil || string(got) != string(identities) {
		t.Errorf("authz identities after reopen = %q, %v", got, err)
	}
	if got, err := r.LoadOrganizerCollections(); err != nil || !reflect.DeepEqual(got, cols) {
		t.Errorf("organizer collections after reopen = %+v, %v; want %+v", got, err, cols)
	}
}
