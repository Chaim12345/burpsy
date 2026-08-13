package scanner

// Technology fingerprinting over the Wappalyzer signature set, for the version-specific
// catalog rows (React Server Components RCE and the other known-CVE checks).
//
// The signature corpus is the reason to take the dependency: a hand-rolled Server:/X-Powered-By:
// matcher recognises the handful of technologies its author thought of and silently misses
// everything else, which reads as "no vulnerable component" — a false negative.

import (
	"fmt"
	"strings"
	"sync"

	"github.com/Masterminds/semver/v3"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type Technology struct {
	Name string
	// Version is empty when the signature matched but carried no version.
	Version string
	CPE     string
	// Categories is the Wappalyzer classification, e.g. "JavaScript frameworks".
	Categories []string
}

// HasVersion separates "detected, version unknown" from "detected at version X". A
// version-gated check must not treat unknown as out of range.
func (t Technology) HasVersion() bool { return t.Version != "" }

func (t Technology) String() string {
	if t.Version == "" {
		return t.Name
	}
	return t.Name + " " + t.Version
}

var (
	wappalyzeOnce sync.Once
	wappalyzeInst *wappalyzer.Wappalyze
	wappalyzeErr  error
)

func wappalyzeClient() (*wappalyzer.Wappalyze, error) {
	wappalyzeOnce.Do(func() {
		wappalyzeInst, wappalyzeErr = wappalyzer.New()
	})
	return wappalyzeInst, wappalyzeErr
}

// Fingerprint identifies technologies from response headers and body.
func Fingerprint(headers map[string][]string, body []byte) ([]Technology, error) {
	client, err := wappalyzeClient()
	if err != nil {
		return nil, fmt.Errorf("fingerprint: %w", err)
	}
	matches := client.FingerprintWithInfo(headers, body)

	out := make([]Technology, 0, len(matches))
	for name, info := range matches {
		// Wappalyzer encodes a detected version as "Name:1.2.3".
		techName, version := name, ""
		if base, ver, ok := strings.Cut(name, ":"); ok {
			techName, version = base, ver
		}
		out = append(out, Technology{
			Name:       techName,
			Version:    version,
			CPE:        info.CPE,
			Categories: info.Categories,
		})
	}
	return out, nil
}

// FindTechnology returns the named technology, case-insensitively.
func FindTechnology(techs []Technology, name string) (Technology, bool) {
	for _, t := range techs {
		if strings.EqualFold(t.Name, name) {
			return t, true
		}
	}
	return Technology{}, false
}

// VersionVerdict keeps "not affected" apart from "cannot tell".
type VersionVerdict int

const (
	// VersionUnknown means the technology was detected without a usable version, or the
	// version did not parse. It is not a clean result.
	VersionUnknown VersionVerdict = iota
	VersionInRange
	VersionOutOfRange
)

func (v VersionVerdict) String() string {
	switch v {
	case VersionUnknown:
		return "version unknown"
	case VersionInRange:
		return "version in affected range"
	case VersionOutOfRange:
		return "version outside affected range"
	}
	return "unknown"
}

// CheckVersionRange evaluates a semver constraint such as ">=18.0.0 <18.3.1" against a
// detected version. An unparseable version or constraint yields VersionUnknown rather than
// a false "not affected".
func CheckVersionRange(version, constraint string) VersionVerdict {
	if strings.TrimSpace(version) == "" {
		return VersionUnknown
	}
	c, err := semver.NewConstraint(constraint)
	if err != nil {
		return VersionUnknown
	}
	v, err := semver.NewVersion(strings.TrimSpace(version))
	if err != nil {
		return VersionUnknown
	}
	if c.Check(v) {
		return VersionInRange
	}
	return VersionOutOfRange
}

// TechnologyInAffectedRange is the version-gated check shape: detected, and within range.
func TechnologyInAffectedRange(techs []Technology, name, constraint string) (VersionVerdict, bool) {
	t, found := FindTechnology(techs, name)
	if !found {
		return VersionUnknown, false
	}
	return CheckVersionRange(t.Version, constraint), true
}
