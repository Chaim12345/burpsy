package scanner

// The gitleaks rule corpus as the secrets module's engine (burpsy-react-ui-8j0d).
//
// gitleaks (MIT, Go) maintains ~220 provider rules — a regex, a keyword prefilter, an entropy floor
// and allowlists per rule — for AWS/GCP/Azure, GitHub/GitLab/Slack/Stripe tokens, private keys and
// the rest. A hand-rolled subset goes stale the way infra_fingerprint.go's comment warns about, which
// is why the corpus is imported as a library (detect.NewDetectorDefaultConfig embeds the shipped
// gitleaks.toml) rather than ported. Only its matcher is used: nothing here reads a filesystem, a git
// history or the network.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"github.com/zricethezav/gitleaks/v8/detect"
	gllog "github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
)

// maxSecretScanBytes bounds one response's scan. ~220 regexes over a multi-megabyte bundle on the
// capture path is real CPU; the first 4 MiB of a body holds the configuration blocks and inlined
// keys this is for, and a finding from a truncated scan says so.
const maxSecretScanBytes = 4 << 20

// excludedGitleaksRules are corpus rules this module does not report.
//
// jwt: a JWT in a response is how every login works, not a leak — reporting one per session would
// bury the findings that matter, and burpsy's JWT checks (infra_jwt.go, jwt_weak.go) already read
// tokens for the weaknesses that ARE findings: alg:none, weak HMAC secrets, missing expiry.
var excludedGitleaksRules = map[string]bool{"jwt": true}

var (
	gitleaksOnce     sync.Once
	gitleaksDetector *detect.Detector
	gitleaksErr      error
)

// gitleaks returns the shared detector, built once. DetectString keeps its findings local to the
// call (only DetectSource accumulates on the detector), so one detector serves every concurrent
// capture — pinned by TestTheSharedGitleaksDetectorIsSafeUnderConcurrentScans under -race.
func gitleaks() (*detect.Detector, error) {
	gitleaksOnce.Do(func() {
		// gitleaks logs through a package-level zerolog logger to stderr; on the capture path that is
		// noise interleaved with burpsy's own structured log.
		gllog.Logger = zerolog.Nop()
		gitleaksDetector, gitleaksErr = detect.NewDetectorDefaultConfig()
	})
	return gitleaksDetector, gitleaksErr
}

// GitleaksRuleCount is how many corpus rules the module runs, for the console's "what is this
// running" line. Zero when the corpus failed to load.
func GitleaksRuleCount() int {
	d, err := gitleaks()
	if err != nil || d == nil {
		return 0
	}
	n := 0
	for id := range d.Config.Rules {
		if !excludedGitleaksRules[id] {
			n++
		}
	}
	return n
}

// GitleaksVersion names the corpus the module embeds.
const GitleaksVersion = "gitleaks v8.30.1"

// gitleaksFindings runs the corpus over one body. Each match is its own finding, carrying the rule,
// the line and column it was found at, and a redacted excerpt; MergeKey makes two different secrets
// on one page two findings, and one secret seen on every page of a host one finding.
//
// covered holds what the module's own provider rules already matched: a generic corpus match whose
// secret sits inside one of those (an Azure AccountKey is a "generic API key" too) is the same key
// reported under a vaguer name, and is dropped.
func gitleaksFindings(module string, body []byte, covered []string) []ResponseFinding {
	d, err := gitleaks()
	if err != nil || d == nil {
		return nil
	}
	truncated := false
	if len(body) > maxSecretScanBytes {
		body, truncated = body[:maxSecretScanBytes], true
	}
	var out []ResponseFinding
	seen := map[string]bool{}
	for _, f := range d.DetectString(string(body)) {
		if excludedGitleaksRules[f.RuleID] || f.Secret == "" {
			continue
		}
		if strings.HasPrefix(f.RuleID, "generic-") && insideAny(f.Secret, covered) {
			continue
		}
		key := secretMergeKey(f.RuleID, f.Secret)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, gitleaksFinding(module, f, key, truncated))
	}
	return out
}

func gitleaksFinding(module string, f report.Finding, key string, truncated bool) ResponseFinding {
	severity, confidence := "high", "firm"
	if strings.HasPrefix(f.RuleID, "generic-") {
		// The generic rule is a labelled high-entropy value with no provider shape behind it, so it
		// is the corpus's least certain match.
		severity, confidence = "medium", "tentative"
	}
	evidence := redactSecret(f.Secret)
	if f.RuleID == "aws-access-token" {
		// An AWS access key ID is a public identifier (IAM listings, CloudTrail), so it is echoed: the
		// operator needs it to know WHICH key leaked. The secret half is never echoed.
		evidence = f.Secret
	}
	detail := fmt.Sprintf("gitleaks rule %s matched at line %d, column %d of the response body. %s",
		f.RuleID, f.StartLine+1, f.StartColumn, f.Description)
	if truncated {
		detail += fmt.Sprintf(" Only the first %d MiB of the body were scanned.", maxSecretScanBytes>>20)
	}
	return ResponseFinding{
		Module:     module,
		Name:       "Secret exposed: " + gitleaksRuleTitle(f.RuleID),
		Severity:   severity,
		Confidence: confidence,
		Detail:     detail,
		Evidence:   evidence,
		MergeKey:   key,
	}
}

// secretMergeKey identifies one secret without carrying it: the rule plus a hash prefix, so the
// finding store can tell two keys apart while the key itself never reaches the store, the console or
// a report through this field.
func secretMergeKey(rule, secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return rule + ":" + hex.EncodeToString(sum[:8])
}

// gitleaksRuleTitle turns a rule id ("github-fine-grained-pat") into a title ("GitHub fine grained
// PAT"). The corpus descriptions are full sentences, which read badly as an issue name.
func gitleaksRuleTitle(id string) string {
	upper := map[string]string{
		"aws": "AWS", "gcp": "GCP", "api": "API", "pat": "PAT", "ssh": "SSH", "id": "ID", "url": "URL",
		"jwt": "JWT", "npm": "npm", "github": "GitHub", "gitlab": "GitLab", "pypi": "PyPI", "sql": "SQL",
		"oauth": "OAuth", "ad": "AD", "sdk": "SDK", "dsn": "DSN", "hmac": "HMAC", "ai": "AI",
	}
	words := strings.Split(id, "-")
	for i, w := range words {
		if u, ok := upper[w]; ok {
			words[i] = u
		} else if i == 0 && w != "" {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

func insideAny(secret string, matches []string) bool {
	for _, m := range matches {
		if strings.Contains(m, secret) {
			return true
		}
	}
	return false
}
