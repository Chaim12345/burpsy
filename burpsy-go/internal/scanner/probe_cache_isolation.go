package scanner

// Probing behind a shared cache.
//
// # The defect this closes
//
// A probe harness replays one captured request with a payload in one place. When a shared cache
// sits in front of the application and its key leaves that place out — a cache keyed on the route
// with the query ignored is the common shape — two things go wrong at once:
//
//  1. The probe is answered from the cache. The first request to the key stores its answer, and
//     every later probe to the same key, whatever its payload, is served that stored answer. A
//     reflection check then sees the FIRST probe's canary (or the baseline's value) and never its
//     own, so a value reflected unescaped reads as "not reflected" and the point is reported clean.
//  2. The probe poisons the entry real visitors are served: a payload sent to the route is stored
//     under the route for the cache's lifetime.
//
// The first is a false negative, the second is a harm, and both have the same fix: every probe
// carries a cache buster the cache provably keys on, with a FRESH value per probe, so each probe is
// a miss of its own entry and no probe ever touches the entry anyone else is served.
//
// # The buster is verified, never assumed
//
// Only a target whose baseline answer reports cache state (X-Cache, CF-Cache-Status, Cache-Status,
// Age, X-Varnish, …: observeCacheState) is considered; a target that says nothing about a cache is
// probed exactly as before. The verification is the cache poisoning check's own (selectBuster), and
// sends CLEAN requests only: buster b1 twice, then b2. b1's repeat a hit and b2 not a hit means the
// buster location is in the key. A query parameter is tried first, then a path parameter
// (";name=value"), which servlet containers and many frameworks route to the same handler while the
// cache sees a different URI.
//
// When the cache reports itself and stores this response but keys neither location, every probe
// would land on the shared entry. The harness then refuses to probe and says why — an untested
// point named as untested, not a clean one. When the cache reports itself but never serves the
// repeat from cache, nothing is stored, nothing can be poisoned, and probing proceeds unbustered.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
)

// errSharedCacheUnisolated is the refusal: probes would be stored where other visitors are served.
var errSharedCacheUnisolated = errors.New("the target reports a shared cache that stores this response, " +
	"and no cache-buster location (query parameter, path parameter) is in its key; probing would " +
	"poison the entry other visitors are served, so no probe was sent")

// rawResponseHeaderMap reads a raw response's header block into a map, values of repeated names
// joined with ", ". Only for the cache-state headers, which observeCacheState reads.
func rawResponseHeaderMap(raw []byte) map[string]string {
	head := raw
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		head = raw[:i]
	} else if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		head = raw[:i]
	}
	out := map[string]string{}
	lines := strings.Split(string(head), "\n")
	for _, line := range lines[min(1, len(lines)):] { // the first line is the status line
		line = strings.TrimSuffix(line, "\r")
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" {
			continue
		}
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if prev, seen := out[name]; seen {
			value = prev + ", " + value
		}
		out[name] = value
	}
	return out
}

// withCacheBusterRaw returns raw with the cache buster added to its request target at loc. A request
// whose first line is not `METHOD target VERSION` with an origin- or absolute-form target is
// returned unchanged.
func withCacheBusterRaw(raw []byte, loc cacheBusterLocation, value string) []byte {
	end := bytes.IndexByte(raw, '\n')
	if end < 0 {
		return raw
	}
	line := string(raw[:end])
	cr := strings.HasSuffix(line, "\r")
	line = strings.TrimSuffix(line, "\r")
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return raw
	}
	target, prefix := parts[1], ""
	if !strings.HasPrefix(target, "/") {
		i := strings.Index(target, "://")
		if i < 0 {
			return raw // authority-form or asterisk-form: no path to carry a buster
		}
		rest := target[i+3:]
		j := strings.IndexAny(rest, "/?")
		if j < 0 {
			prefix, target = target, "/"
		} else {
			prefix, target = target[:i+3+j], rest[j:]
		}
		if strings.HasPrefix(target, "?") {
			target = "/" + target
		}
	}
	newLine := parts[0] + " " + prefix + applyCacheBuster(target, loc, value) + " " + parts[2]
	if cr {
		newLine += "\r"
	}
	out := make([]byte, 0, len(raw)+len(newLine)-len(line))
	out = append(out, newLine...)
	return append(out, raw[end:]...)
}

// IsolateFromSharedCache makes every later probe of this harness carry a fresh, verified-keyed cache
// buster when the target reports a shared cache (see the file comment). It returns a note describing
// what was decided, empty when the target reports no cache, and errSharedCacheUnisolated when the
// cache stores this response under a key no buster location reaches.
//
// It must be called before the first probe; the baseline it reads was sent without a buster.
func (h *ProbeHarness) IsolateFromSharedCache(ctx context.Context) (string, error) {
	if h == nil || h.exchange == nil {
		return "", nil
	}
	if m := strings.ToUpper(h.exchange.Method); m != "GET" && m != "HEAD" && m != "" {
		return "", nil // a shared cache stores GET and HEAD answers only
	}
	if observeCacheState(rawResponseHeaderMap(h.baseline.Raw)) == cacheUnknown {
		return "", nil
	}
	stored := false
	var notes []string
	for _, loc := range []cacheBusterLocation{busterQuery, busterPathParam} {
		b1, b2 := freshBuster(), freshBuster()
		r1, err := h.send(ctx, withCacheBusterRaw(h.reqBytes, loc, b1))
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s buster: %v", loc, err))
			continue
		}
		if r1.Status != h.baseline.Status {
			notes = append(notes, fmt.Sprintf("%s buster changed the status (%d, baseline %d)", loc, r1.Status, h.baseline.Status))
			continue
		}
		r2, err2 := h.send(ctx, withCacheBusterRaw(h.reqBytes, loc, b1))
		r3, err3 := h.send(ctx, withCacheBusterRaw(h.reqBytes, loc, b2))
		if err2 != nil || err3 != nil {
			notes = append(notes, loc.String()+" buster: no response")
			continue
		}
		o2 := observeCacheState(rawResponseHeaderMap(r2.Raw))
		o3 := observeCacheState(rawResponseHeaderMap(r3.Raw))
		switch {
		case o2 == cacheHit && o3 != cacheHit:
			l := loc
			h.buster = &l
			return fmt.Sprintf("the target reports a shared cache; every probe carried a fresh %s cache buster "+
				"(%s), verified to be in the cache key with clean requests (repeat %s, fresh value %s), so each "+
				"probe was answered for itself and none was stored where other visitors are served",
				loc, cachePoisonBusterName, o2, o3), nil
		case o2 == cacheHit:
			stored = true
			notes = append(notes, loc.String()+" buster is not in the cache key")
		default:
			notes = append(notes, fmt.Sprintf("%s buster: the repeat was not served from cache (%s)", loc, o2))
		}
	}
	if stored {
		return "", fmt.Errorf("%w (%s)", errSharedCacheUnisolated, strings.Join(notes, "; "))
	}
	return "the target reports cache state but served no repeat from cache, so probes were sent unbustered: " +
		strings.Join(notes, "; "), nil
}
