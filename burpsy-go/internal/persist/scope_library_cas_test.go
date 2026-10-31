package persist

// ---- Digest-checked scope-library writes (burpsy-react-ui-e365 review binding) ------------------
//
// A confirmed library call binds the document the operator reviewed: these pin that a write lands
// only while the stored bytes still hash to the reviewed digest (or to "absent" for a name that
// did not exist), that a mismatch writes nothing, and that the digest is over the exact stored
// bytes — re-read from the database, not re-serialised, so no serialisation drift can make the
// check pass against content that changed.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"

	_ "modernc.org/sqlite"
)

func TestLoadScopeLibraryWithDigestHashesTheExactStoredBytes(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "project.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	rules := []*core.ScopeRule{core.NewScopeRule(core.ScopeInclude, "app.test")}
	if _, err := store.SaveScopeLibrary("engagement", rules); err != nil {
		t.Fatalf("save: %v", err)
	}
	_, digest, found, err := store.LoadScopeLibraryWithDigest("engagement")
	if err != nil || !found {
		t.Fatalf("LoadScopeLibraryWithDigest = (found %v, err %v)", found, err)
	}
	// Read the column through a SECOND connection and hash it by hand: the digest must be of the
	// stored bytes as they lie, or a serialisation change between write and check would pass
	// against altered content.
	db, err := sql.Open("sqlite", filepath.Join(dir, "project.db"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db.Close()
	var body string
	if err := db.QueryRow(`SELECT rules_json FROM scope_libraries WHERE name = 'engagement'`).Scan(&body); err != nil {
		t.Fatalf("direct read: %v", err)
	}
	sum := sha256.Sum256([]byte(body))
	if want := hex.EncodeToString(sum[:]); digest != want {
		t.Fatalf("digest = %s, want the sha256 of the stored bytes %s", digest, want)
	}
	// A missing name reports absence with no digest.
	if _, d, found, err := store.LoadScopeLibraryWithDigest("nope"); err != nil || found || d != "" {
		t.Fatalf("missing library = (%q, %v, %v), want no digest, not found, no error", d, found, err)
	}
}

func TestSaveScopeLibraryIfUnchangedWritesOnlyOverTheReviewedState(t *testing.T) {
	store := openStore(t)
	one := []*core.ScopeRule{core.NewScopeRule(core.ScopeInclude, "one.test")}

	// Reviewed as absent: the save creates, and reports no replacement.
	replaced, conflict, err := store.SaveScopeLibraryIfUnchanged("engagement", one, ScopeLibraryAbsent)
	if err != nil || conflict || replaced {
		t.Fatalf("first save = (replaced %v, conflict %v, err %v), want all false", replaced, conflict, err)
	}

	// Reviewed as absent, but a library now exists: conflict, and the existing document is intact.
	two := []*core.ScopeRule{core.NewScopeRule(core.ScopeInclude, "two.test")}
	if _, conflict, err := store.SaveScopeLibraryIfUnchanged("engagement", two, ScopeLibraryAbsent); !conflict || err != nil {
		t.Fatalf("save over an unreviewed existing library = (conflict %v, err %v), want conflict", conflict, err)
	}
	if got, found, _ := store.LoadScopeLibrary("engagement"); !found || len(got) != 1 || got[0].Pattern != "one.test" {
		t.Fatalf("a conflicted save wrote anyway: %+v", got)
	}

	// Reviewed at the current digest: the overwrite lands and reports the replacement.
	_, digest, _, err := store.LoadScopeLibraryWithDigest("engagement")
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	replaced, conflict, err = store.SaveScopeLibraryIfUnchanged("engagement", two, digest)
	if err != nil || conflict || !replaced {
		t.Fatalf("overwrite = (replaced %v, conflict %v, err %v), want (true, false, nil)", replaced, conflict, err)
	}
	if got, _, _ := store.LoadScopeLibrary("engagement"); len(got) != 1 || got[0].Pattern != "two.test" {
		t.Fatalf("overwrite did not land: %+v", got)
	}

	// The digest just spent is now stale: replaying it conflicts and writes nothing.
	if _, conflict, err := store.SaveScopeLibraryIfUnchanged("engagement", one, digest); !conflict || err != nil {
		t.Fatalf("replayed digest = (conflict %v, err %v), want conflict", conflict, err)
	}
	if got, _, _ := store.LoadScopeLibrary("engagement"); len(got) != 1 || got[0].Pattern != "two.test" {
		t.Fatalf("a replayed save wrote anyway: %+v", got)
	}
}

func TestDeleteScopeLibraryIfUnchangedDeletesOnlyTheReviewedDocument(t *testing.T) {
	store := openStore(t)
	one := []*core.ScopeRule{core.NewScopeRule(core.ScopeInclude, "one.test")}
	if _, err := store.SaveScopeLibrary("engagement", one); err != nil {
		t.Fatalf("save: %v", err)
	}
	_, digest, _, err := store.LoadScopeLibraryWithDigest("engagement")
	if err != nil {
		t.Fatalf("digest: %v", err)
	}

	// Replaced since the review: refuse, and the replacement survives.
	two := []*core.ScopeRule{core.NewScopeRule(core.ScopeInclude, "two.test")}
	if _, err := store.SaveScopeLibrary("engagement", two); err != nil {
		t.Fatalf("replace: %v", err)
	}
	deleted, conflict, err := store.DeleteScopeLibraryIfUnchanged("engagement", digest)
	if err != nil || deleted || !conflict {
		t.Fatalf("delete after replacement = (deleted %v, conflict %v, err %v), want conflict only", deleted, conflict, err)
	}
	if _, found, _ := store.LoadScopeLibrary("engagement"); !found {
		t.Fatal("a conflicted delete removed the library")
	}

	// Reviewed at the current digest: the delete lands.
	_, digest2, _, _ := store.LoadScopeLibraryWithDigest("engagement")
	deleted, conflict, err = store.DeleteScopeLibraryIfUnchanged("engagement", digest2)
	if err != nil || conflict || !deleted {
		t.Fatalf("delete = (deleted %v, conflict %v, err %v), want (true, false, nil)", deleted, conflict, err)
	}

	// Gone, when content was expected: a change since the review — conflict, not a quiet 404.
	if _, conflict, err := store.DeleteScopeLibraryIfUnchanged("engagement", digest2); !conflict || err != nil {
		t.Fatalf("delete of a vanished library = (conflict %v, err %v), want conflict", conflict, err)
	}
	// Gone, when absence was expected: the reviewed state holds; there is just nothing to remove.
	deleted, conflict, err = store.DeleteScopeLibraryIfUnchanged("engagement", ScopeLibraryAbsent)
	if err != nil || conflict || deleted {
		t.Fatalf("delete with absence expected = (deleted %v, conflict %v, err %v), want all false", deleted, conflict, err)
	}
}

func TestScopeLibraryCASWritesSerialiseAgainstConcurrentWriters(t *testing.T) {
	store := openStore(t)
	seed := []*core.ScopeRule{core.NewScopeRule(core.ScopeInclude, "seed.test")}
	if _, err := store.SaveScopeLibrary("engagement", seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, digest, _, err := store.LoadScopeLibraryWithDigest("engagement")
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	// Ten writers hold the SAME reviewed digest: exactly one may win, the rest must conflict,
	// and the stored document must be the winner's — a check-then-act gap would let several
	// through, each believing it overwrote the reviewed content.
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins, conflicts := 0, 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rules := []*core.ScopeRule{core.NewScopeRule(core.ScopeInclude, fmt.Sprintf("w%d.test", i))}
			_, conflict, err := store.SaveScopeLibraryIfUnchanged("engagement", rules, digest)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Errorf("writer %d errored: %v", i, err)
				return
			}
			if conflict {
				conflicts++
			} else {
				wins++
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 || conflicts != 9 {
		t.Fatalf("wins=%d conflicts=%d, want exactly one winner and nine conflicts", wins, conflicts)
	}
	got, found, err := store.LoadScopeLibrary("engagement")
	if err != nil || !found || len(got) != 1 || !strings.HasPrefix(got[0].Pattern, "w") {
		t.Fatalf("stored document after the race = %+v (found %v, err %v)", got, found, err)
	}
}
