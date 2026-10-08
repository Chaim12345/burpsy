package intruder

// Anomaly ranking (burpsy-react-ui-pglp): Burp's ResponseVariationsAnalyzer and its "default
// Anomaly-based ranking algorithm" (Montoya: variantAttributes, RankingUtils.rank). An attack's
// interesting rows are the ones whose responses differ from the crowd; this ranks every detail row
// by how rare its response's attributes are across the attack, and names the attributes that varied
// at all.
//
// The attributes are a subset of Burp's AttributeType set that can be read off one response cheaply
// and deterministically: STATUS_CODE, CONTENT_TYPE, CONTENT_LENGTH (the body length), WORD_COUNT,
// LINE_COUNT, PAGE_TITLE, LOCATION, COOKIE_NAMES. A failed attempt's only attribute is its outcome (error or timeout); a
// response's outcome is "response", so a lone failure among responses stands out.
// The algorithm is burpsy's own — Burp does not document its weights: an attribute that never varies
// says nothing and is ignored; for the rest, a row scores the sum of -ln(frequency of its value), so
// a value seen once in a thousand rows outweighs one seen in half of them. Rank 1 is the most
// anomalous; equal scores share a rank.

import (
	"bytes"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// responseAttributes reads the ranked attributes off one response.
func responseAttributes(raw []byte, status *int, length int, cookies []string) map[string]string {
	attrs := map[string]string{"outcome": "response", "content_length": strconv.Itoa(length)}
	if status != nil {
		attrs["status_code"] = strconv.Itoa(*status)
	}
	head, body, _ := bytes.Cut(raw, []byte("\r\n\r\n"))
	for _, line := range bytes.Split(head, []byte("\r\n"))[1:] {
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		switch strings.ToLower(string(bytes.TrimSpace(name))) {
		case "content-type":
			ct, _, _ := strings.Cut(string(bytes.TrimSpace(value)), ";")
			attrs["content_type"] = strings.ToLower(strings.TrimSpace(ct))
		case "location":
			attrs["location"] = string(bytes.TrimSpace(value))
		}
	}
	attrs["word_count"] = strconv.Itoa(len(bytes.Fields(body)))
	attrs["line_count"] = strconv.Itoa(bytes.Count(body, []byte("\n")) + 1)
	if m := titleRe.FindSubmatch(body); m != nil {
		attrs["page_title"] = strings.TrimSpace(string(m[1]))
	}
	if len(cookies) > 0 {
		names := append([]string{}, cookies...)
		sort.Strings(names)
		attrs["cookie_names"] = strings.Join(names, ",")
	}
	return attrs
}

// rankAnomalies sets AnomalyRank on every attempt that has attributes and returns the attributes
// that varied across them, sorted.
func rankAnomalies(attempts []Attempt, attrs map[int]map[string]string) []string {
	n := 0
	keys := map[string]bool{}
	for _, a := range attempts {
		if m, ok := attrs[a.Ordinal]; ok {
			n++
			for k := range m {
				keys[k] = true
			}
		}
	}
	variant := []string{}
	if n < 2 {
		return variant
	}
	counts := map[string]map[string]int{}
	for k := range keys {
		counts[k] = map[string]int{}
		for _, a := range attempts {
			if m, ok := attrs[a.Ordinal]; ok {
				counts[k][m[k]]++
			}
		}
		if len(counts[k]) > 1 {
			variant = append(variant, k)
		}
	}
	sort.Strings(variant)
	scores := make([]float64, len(attempts))
	for i, a := range attempts {
		m, ok := attrs[a.Ordinal]
		if !ok {
			scores[i] = -1
			continue
		}
		for _, k := range variant {
			scores[i] += -math.Log(float64(counts[k][m[k]]) / float64(n))
		}
	}
	distinct := []float64{}
	seen := map[float64]bool{}
	for i, sc := range scores {
		if sc < 0 {
			continue
		}
		r := math.Round(sc*1e9) / 1e9
		scores[i] = r
		if !seen[r] {
			seen[r] = true
			distinct = append(distinct, r)
		}
	}
	sort.Sort(sort.Reverse(sort.Float64Slice(distinct)))
	rank := map[float64]int{}
	for i, sc := range distinct {
		rank[sc] = i + 1
	}
	for i := range attempts {
		if scores[i] >= 0 {
			attempts[i].AnomalyRank = rank[scores[i]]
		}
	}
	return variant
}
