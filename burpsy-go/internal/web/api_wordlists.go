package web

// The wordlist manager (burpsy-react-ui-kal): /api/wordlists is the one inventory of the
// payload corpora an operator can point a tool at — the six lists bundled into the binary
// and the uploads that already land in burpsy's upload directory. It exists so an operator
// points ONCE rather than per attack: Intruder's file-source field and content discovery's
// wordlist field both read this inventory, and each entry carries the count the attack will
// actually see.
//
// # What the count means, and why it is not the file's header claim
//
// Builtin counts come from reading the file itself (BuiltinWordlistCount), never from the
// provenance header's stated number — drift between the two is a defect, and the count an
// operator plans an attack around is the count that will fire (blank lines skipped, '#'
// comment header lines skipped for builtins). Upload counts are what the upload handler
// already computed at store time: blank lines skipped, per-item lengths not yet checked
// (Resolve does that at run time, and a list with one over-long line is still a list).
import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/burpsy-go/burpsy/internal/intruder"
)

// wordlistEntry is one row of the inventory.
type wordlistEntry struct {
	// Name is what the operator selects: the builtin list's name, or the upload's original
	// display name (the stored path is random by design — see the upload handler's
	// path-traversal note — and not a thing an operator should have to know).
	Name string `json:"name"`
	// Kind is "builtin" or "upload".
	Kind string `json:"kind"`
	// Ref is the value the consuming tool takes: "builtin:<name>" for bundled lists, the
	// absolute path for uploads — both already resolvable by the existing consumers.
	Ref string `json:"ref"`
	// Lines is the payload count the tool will see.
	Lines int `json:"lines"`
}

// handleWordlists serves GET /api/wordlists: the inventory. No POST here — uploads keep
// their own door (POST /api/intruder/payload-files), because an upload's limits and
// path-traversal rules belong to the upload handler, not to a listing.
func (s *Server) handleWordlists(w http.ResponseWriter, r *http.Request) {
	out := make([]wordlistEntry, 0, 8)
	for _, name := range intruder.BuiltinWordlistNames() {
		out = append(out, wordlistEntry{
			Name:  name,
			Kind:  "builtin",
			Ref:   "builtin:" + name,
			Lines: intruder.BuiltinWordlistCount(name),
		})
	}
	// Uploads: listed newest-first (the operator's most recent list is the one they are
	// about to use), each with its stored line count if it is recoverable, and skipped
	// without a word of complaint when the directory has not been created yet (no upload
	// ever happening is a normal state, not an error to report).
	if dir, err := s.payloadUploadDir(); err == nil {
		if entries, err := os.ReadDir(dir); err == nil {
			type uploaded struct {
				path  string
				atime int64
				name  string
			}
			var ups []uploaded
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				info, err := e.Info()
				if err != nil {
					continue
				}
				ups = append(ups, uploaded{
					path:  filepath.Join(dir, e.Name()),
					atime: info.ModTime().UnixMilli(),
					name:  e.Name(),
				})
			}
			// newest first
			for i := 1; i < len(ups); i++ {
				for j := i; j > 0 && ups[j].atime > ups[j-1].atime; j-- {
					ups[j], ups[j-1] = ups[j-1], ups[j]
				}
			}
			for _, up := range ups {
				lines := 0
				if raw, err := os.ReadFile(up.path); err == nil {
					for _, line := range strings.Split(string(raw), "\n") {
						if strings.TrimSpace(line) != "" {
							lines++
						}
					}
				}
				out = append(out, wordlistEntry{
					Name:  up.name,
					Kind:  "upload",
					Ref:   up.path,
					Lines: lines,
				})
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"wordlists": out,
		"note": "builtin entries resolve as {\"type\":\"file\",\"filename\":\"builtin:<name>\"}; " +
			"uploads resolve by their stored path. Counts are the lines the attack will see, " +
			"blank lines already skipped.",
	})
}
