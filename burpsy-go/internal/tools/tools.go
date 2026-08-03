package tools

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// Decoder provides various decoding functions.
type Decoder struct{}

// NewDecoder creates a new decoder instance.
func NewDecoder() *Decoder {
	return &Decoder{}
}

// DecodeBase64 decodes base64 encoded string.
func (d *Decoder) DecodeBase64(input string) (string, error) {
	// Try standard base64
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err == nil {
		return string(decoded), nil
	}

	// Try URL-safe base64
	decoded, err = base64.URLEncoding.DecodeString(input)
	if err == nil {
		return string(decoded), nil
	}

	return "", fmt.Errorf("failed to decode base64: %v", err)
}

// EncodeBase64 encodes string to base64.
func (d *Decoder) EncodeBase64(input string) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}

// DecodeHex decodes hex encoded string.
func (d *Decoder) DecodeHex(input string) (string, error) {
	input = strings.ReplaceAll(input, " ", "")
	input = strings.TrimPrefix(input, "0x")

	decoded, err := hex.DecodeString(input)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex: %v", err)
	}

	return string(decoded), nil
}

// EncodeHex encodes string to hex.
func (d *Decoder) EncodeHex(input string) string {
	return hex.EncodeToString([]byte(input))
}

// DecodeURL decodes URL encoded string.
func (d *Decoder) DecodeURL(input string) (string, error) {
	decoded, err := url.QueryUnescape(input)
	if err != nil {
		return "", fmt.Errorf("failed to decode URL: %v", err)
	}
	return decoded, nil
}

// EncodeURL encodes string to URL format.
func (d *Decoder) EncodeURL(input string) string {
	return url.QueryEscape(input)
}

// DecodeHTML decodes HTML entities. The replacements are applied in a fixed
// order — &amp; first — rather than via a map, because map iteration order is
// randomised and the order matters: decoding "&amp;lt;" yields "<" only when
// "&amp;" is replaced before "&lt;". A deterministic order gives a deterministic
// result across runs.
func (d *Decoder) DecodeHTML(input string) string {
	replacements := []struct{ from, to string }{
		{"&amp;", "&"},
		{"&lt;", "<"},
		{"&gt;", ">"},
		{"&quot;", "\""},
		{"&#39;", "'"},
		{"&nbsp;", " "},
	}
	result := input
	for _, r := range replacements {
		result = strings.ReplaceAll(result, r.from, r.to)
	}
	return result
}

// EncodeHTML encodes special characters to HTML entities.
func (d *Decoder) EncodeHTML(input string) string {
	result := strings.ReplaceAll(input, "&", "&amp;")
	result = strings.ReplaceAll(result, "<", "&lt;")
	result = strings.ReplaceAll(result, ">", "&gt;")
	result = strings.ReplaceAll(result, "\"", "&quot;")
	result = strings.ReplaceAll(result, "'", "&#39;")
	return result
}

// DecodeJWT decodes a JWT token into its parts.
func (d *Decoder) DecodeJWT(token string) (header, payload, signature string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid JWT format")
	}

	header, err = d.DecodeBase64(parts[0])
	if err != nil {
		return "", "", "", fmt.Errorf("failed to decode header: %v", err)
	}

	payload, err = d.DecodeBase64(parts[1])
	if err != nil {
		return "", "", "", fmt.Errorf("failed to decode payload: %v", err)
	}

	signature = parts[2]
	return header, payload, signature, nil
}

// EncodeJWT encodes JWT parts.
func (d *Decoder) EncodeJWT(header, payload string, data []byte) string {
	h := d.EncodeBase64(header)
	p := d.EncodeBase64(payload)
	s := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("%s.%s.%s", h, p, s)
}

// ToASCII converts string to ASCII representation.
func (d *Decoder) ToASCII(input string) string {
	var result strings.Builder
	for _, r := range input {
		if r > unicode.MaxASCII {
			result.WriteString(fmt.Sprintf("\\u%04x", r))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// FromASCII converts ASCII representation back to string.
func (d *Decoder) FromASCII(input string) (string, error) {
	var result strings.Builder
	i := 0
	for i < len(input) {
		if i+5 < len(input) && input[i:i+2] == "\\u" {
			code, err := hex.DecodeString(input[i+2 : i+6])
			if err == nil {
				result.Write(code)
				i += 6
				continue
			}
		}
		result.WriteByte(input[i])
		i++
	}
	return result.String(), nil
}

// Rot13 applies ROT13 cipher.
func (d *Decoder) Rot13(input string) string {
	var result strings.Builder
	for _, r := range input {
		switch {
		case r >= 'A' && r <= 'Z':
			result.WriteRune('A' + (r-'A'+13)%26)
		case r >= 'a' && r <= 'z':
			result.WriteRune('a' + (r-'a'+13)%26)
		default:
			result.WriteRune(r)
		}
	}
	return result.String()
}

// Reverse reverses a string.
func (d *Decoder) Reverse(input string) string {
	runes := []rune(input)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// Compare compares two strings and returns differences.
type ComparisonResult struct {
	Identical   bool
	Differences []Difference
	LengthDiff  int
}

type Difference struct {
	Position int
	Expected byte
	Actual   byte
}

// Compare compares two byte slices.
func (d *Decoder) Compare(a, b []byte) *ComparisonResult {
	result := &ComparisonResult{
		Identical: true,
	}

	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	result.LengthDiff = len(a) - len(b)

	for i := 0; i < minLen; i++ {
		if a[i] != b[i] {
			result.Identical = false
			result.Differences = append(result.Differences, Difference{
				Position: i,
				Expected: a[i],
				Actual:   b[i],
			})
		}
	}

	if len(a) != len(b) {
		result.Identical = false
	}

	return result
}

// Hash utilities
type Hasher struct{}

// NewHasher creates a new hasher.
func NewHasher() *Hasher {
	return &Hasher{}
}

// MD5 computes MD5 hash.
func (h *Hasher) MD5(input string) string {
	hash := md5.Sum([]byte(input))
	return fmt.Sprintf("%x", hash)
}

// SHA1 computes SHA1 hash.
func (h *Hasher) SHA1(input string) string {
	hash := sha1.Sum([]byte(input))
	return fmt.Sprintf("%x", hash)
}

// SHA256 computes SHA256 hash.
func (h *Hasher) SHA256(input string) string {
	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", hash)
}

// SHA512 computes SHA512 hash.
func (h *Hasher) SHA512(input string) string {
	hash := sha512.Sum512([]byte(input))
	return fmt.Sprintf("%x", hash)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Grep searches for patterns in text.
func Grep(text, pattern string, ignoreCase bool) []string {
	var results []string

	searchPattern := pattern

	if ignoreCase {
		text = strings.ToLower(text)
		searchPattern = strings.ToLower(pattern)
	}

	lines := strings.Split(text, "\n")
	for _, line := range lines {
		checkLine := line
		if ignoreCase {
			checkLine = strings.ToLower(line)
		}
		if strings.Contains(checkLine, searchPattern) {
			results = append(results, line)
		}
	}

	return results
}

// ExtractRegex extracts all matches of a regex pattern.
func ExtractRegex(text, pattern string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return []string{}
	}
	return re.FindAllString(text, -1)
}
