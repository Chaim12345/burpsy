package vulnapp

// Insecure deserialization (burpsy-react-ui-0vzb.10).
//
// Nothing here deserializes anything. Each vulnerable endpoint is a small, strict PARSER of one
// format that answers the way the real deserializer's caller would - ClassNotFoundException for a
// Java stream naming an unknown class, StreamCorruptedException for a corrupted one, PHP's
// __PHP_Incomplete_Class for an unknown class and an "Error at offset" notice for a malformed string,
// and so on. No class is ever loaded and no code runs; the answers are all the scanner's
// differential reads.
//
// The safe twins carry the same kind of value and treat it as an opaque token: a server-side lookup
// or an HMAC checked before any parsing. Several echo the value they refused, so a detector that
// compared raw bodies would see the echo differ between its two probes and fire; the scanner has to
// mask what it sent to stay quiet.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

const deserRow = "Insecure deserialization"

// deserJavaSeedClass is the class the seeded Java profile stream names.
const deserJavaSeedClass = "com.example.Profile"

// deserJavaSeed is a Java object stream of deserJavaSeedClass with no fields, base64-encoded.
var deserJavaSeed = base64.StdEncoding.EncodeToString(deserJavaStream(deserJavaSeedClass))

func deserJavaStream(cls string) []byte {
	b := []byte{0xAC, 0xED, 0x00, 0x05, 0x73, 0x72, byte(len(cls) >> 8), byte(len(cls))}
	b = append(b, cls...)
	return append(b, 0, 0, 0, 0, 0, 0, 0, 1, 0x02, 0x00, 0x00, 0x78, 0x70)
}

// deserPickleSeed is base64 of a protocol-4 pickle of the int 5.
var deserPickleSeed = base64.StdEncoding.EncodeToString([]byte{0x80, 0x04, 'K', 5, '.'})

// deserPHPSeed is a PHP serialize() cart, percent-encoded for the query string.
const deserPHPSeed = `O%3A4%3A%22Cart%22%3A1%3A%7Bs%3A5%3A%22items%22%3Bi%3A3%3B%7D`

// deserSecret signs the safe twins' tokens. It is a fixture constant: nothing here protects data.
var deserSecret = []byte("vulnapp-deserialization-fixture-key")

func deserSign(payload string) string {
	m := hmac.New(sha256.New, deserSecret)
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}

func deserializationEndpoints() []Endpoint {
	cookie := func(v string) map[string]string { return map[string]string{"Cookie": v} }
	return []Endpoint{
		{Path: "/deser/java/profile", Row: deserRow, RequestHeaders: cookie("profile=" + deserJavaSeed),
			Note: "reads the profile cookie as a Java object stream: ClassNotFoundException for an unknown " +
				"class, StreamCorruptedException for a bad type code (echoing the class name)"},
		{Path: "/deser/safe/java/profile", Row: deserRow, Safe: true, RequestHeaders: cookie("profile=" + deserJavaSeed),
			Note: "treats the same cookie as an opaque token looked up server-side; echoes an unknown one"},

		{Path: "/deser/php/cart?cart=" + deserPHPSeed, Row: deserRow,
			Note: "passes cart to a strict unserialize(): __PHP_Incomplete_Class for an unknown class, an " +
				"'Error at offset' notice for malformed text"},
		{Path: "/deser/safe/php/cart?cart=" + deserPHPSeed + "%7C" + deserSign("O:4:\"Cart\":1:{s:5:\"items\";i:3;}"),
			Row: deserRow, Safe: true,
			Note: "same serialize() text with an HMAC after '|', verified before parsing; echoes a refused value"},

		{Path: "/deser/pickle/session", Row: deserRow, RequestHeaders: cookie("session=" + deserPickleSeed),
			Note: "unpickles the session cookie (ints and STOP only); UnpicklingError for any other opcode"},
		{Path: "/deser/safe/pickle/session", Row: deserRow, Safe: true, RequestHeaders: cookie("session=" + deserPickleSeed),
			Note: "treats the same cookie as an opaque session id; echoes an unknown one"},

		{Path: "/deser/activity", Row: deserRow, RequestHeaders: cookie("activity=seed"),
			Note: "an opaque cookie read as base64 JSON whose @class names the class to build: a known class " +
				"loads, an unknown one fails; plain JSON without @class fails too"},
		{Path: "/deser/safe/activity", Row: deserRow, Safe: true, RequestHeaders: cookie("activity=seed"),
			Note: "same cookie, HMAC-signed (base64 JSON '.' signature) and verified before any parsing"},

		{Path: "/deser/prefs", Row: deserRow, RequestHeaders: cookie("prefs=seed"),
			Note: "an opaque cookie read as unsigned base64 JSON bound to one fixed type (no @class): the " +
				"unsigned-state form, reported low/tentative"},
		{Path: "/deser/safe/prefs-param?prefs=e30%3D", Row: deserRow, Safe: true,
			Note: "the same unsigned base64 JSON binding in a QUERY parameter: API input, not client-held " +
				"state, so the unsigned-state probe is not run there"},
	}
}

func registerDeserialization(mux *http.ServeMux) {
	mux.HandleFunc("/deser/java/profile", deserJavaProfile)
	mux.HandleFunc("/deser/safe/java/profile", deserOpaqueCookie("profile", deserJavaSeed, "profile"))
	mux.HandleFunc("/deser/php/cart", deserPHPCart)
	mux.HandleFunc("/deser/safe/php/cart", deserSafePHPCart)
	mux.HandleFunc("/deser/pickle/session", deserPickleSession)
	mux.HandleFunc("/deser/safe/pickle/session", deserOpaqueCookie("session", deserPickleSeed, "session"))
	mux.HandleFunc("/deser/activity", deserActivity)
	mux.HandleFunc("/deser/safe/activity", deserSafeActivity)
	mux.HandleFunc("/deser/prefs", deserPrefs(func(r *http.Request) string {
		c, err := r.Cookie("prefs")
		if err != nil {
			return ""
		}
		return c.Value
	}))
	mux.HandleFunc("/deser/safe/prefs-param", deserPrefs(func(r *http.Request) string { return r.URL.Query().Get("prefs") }))
}

func deserText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func deserCookieBytes(r *http.Request, name string) ([]byte, bool) {
	c, err := r.Cookie(name)
	if err != nil {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(c.Value); err == nil {
			return b, true
		}
	}
	return nil, false
}

// deserJavaProfile answers like an ObjectInputStream.readObject caller.
func deserJavaProfile(w http.ResponseWriter, r *http.Request) {
	b, ok := deserCookieBytes(r, "profile")
	if !ok {
		deserText(w, 400, "profile cookie missing or not base64")
		return
	}
	if len(b) < 8 || b[0] != 0xAC || b[1] != 0xED || b[2] != 0x00 || b[3] != 0x05 {
		deserText(w, 500, "java.io.StreamCorruptedException: invalid stream header")
		return
	}
	if b[4] != 0x73 && b[4] != 0x70 {
		deserText(w, 500, fmt.Sprintf("java.io.StreamCorruptedException: invalid type code: %02X", b[4]))
		return
	}
	if b[5] != 0x72 {
		deserText(w, 500, fmt.Sprintf("java.io.StreamCorruptedException: invalid type code: %02X", b[5]))
		return
	}
	n := int(binary.BigEndian.Uint16(b[6:8]))
	if len(b) < 8+n {
		deserText(w, 500, "java.io.EOFException")
		return
	}
	cls := string(b[8 : 8+n])
	if cls != deserJavaSeedClass {
		deserText(w, 500, "java.lang.ClassNotFoundException: "+cls)
		return
	}
	deserText(w, 200, "profile loaded")
}

// deserOpaqueCookie is a safe twin: the cookie is a key into a server-side table holding one entry.
func deserOpaqueCookie(name, known, what string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(name)
		if err != nil {
			deserText(w, 401, "no "+what)
			return
		}
		if c.Value == known {
			deserText(w, 200, what+" found")
			return
		}
		deserText(w, 401, "unknown "+what+" token: "+c.Value)
	}
}

var deserPHPObjectHead = regexp.MustCompile(`^O:(\d+):"`)

// deserUnserialize is a strict parser for the one shape the fixture uses: O:<n>:"<class>":<k>:{...}
// with k string-keyed int or string members. It returns the class name, or an error offset.
func deserUnserialize(s string) (string, bool) {
	m := deserPHPObjectHead.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	n, _ := strconv.Atoi(m[1])
	rest := s[len(m[0]):]
	if len(rest) < n+2 || rest[n:n+2] != `":` {
		return "", false
	}
	cls := rest[:n]
	rest = rest[n+2:]
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return "", false
	}
	k, err := strconv.Atoi(rest[:colon])
	if err != nil || !strings.HasPrefix(rest[colon+1:], "{") {
		return "", false
	}
	rest = rest[colon+2:]
	member := regexp.MustCompile(`^(?:s:(\d+):"([^"]*)";|i:-?\d+;)`)
	for i := 0; i < 2*k; i++ {
		mm := member.FindStringSubmatch(rest)
		if mm == nil {
			return "", false
		}
		if mm[1] != "" {
			if l, _ := strconv.Atoi(mm[1]); l != len(mm[2]) {
				return "", false
			}
		}
		rest = rest[len(mm[0]):]
	}
	if rest != "}" {
		return "", false
	}
	return cls, true
}

func deserPHPCart(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("cart")
	cls, ok := deserUnserialize(v)
	switch {
	case !ok:
		deserText(w, 200, fmt.Sprintf("Notice: unserialize(): Error at offset 0 of %d bytes. Your cart is empty.", len(v)))
	case cls == "Cart":
		deserText(w, 200, "Your cart: 3 items.")
	default:
		deserText(w, 200, "Warning: Cart expected, __PHP_Incomplete_Class given. Your cart was reset.")
	}
}

func deserSafePHPCart(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("cart")
	payload, sig, ok := strings.Cut(v, "|")
	if !ok || !hmac.Equal([]byte(sig), []byte(deserSign(payload))) {
		deserText(w, 400, "cart signature invalid: "+v)
		return
	}
	if _, ok := deserUnserialize(payload); !ok {
		deserText(w, 500, "internal error")
		return
	}
	deserText(w, 200, "Your cart: 3 items.")
}

// deserPickleSession answers like a pickle.loads caller that accepts only ints.
func deserPickleSession(w http.ResponseWriter, r *http.Request) {
	b, ok := deserCookieBytes(r, "session")
	if !ok {
		deserText(w, 400, "bad session cookie")
		return
	}
	var val int
	i := 0
	if len(b) >= 2 && b[0] == 0x80 {
		i = 2
	}
	for i < len(b) {
		switch op := b[i]; op {
		case 'K':
			if i+1 >= len(b) {
				deserText(w, 500, "_pickle.UnpicklingError: pickle data was truncated")
				return
			}
			val = int(b[i+1])
			i += 2
		case '.':
			deserText(w, 200, fmt.Sprintf("Welcome back, visitor #%d", val))
			return
		default:
			deserText(w, 500, fmt.Sprintf("_pickle.UnpicklingError: invalid load key, '\\x%02x'.", op))
			return
		}
	}
	deserText(w, 500, "EOFError: Ran out of input")
}

var deserActivityKnown = map[string]bool{"java.util.HashMap": true, "java.util.TreeMap": true, "com.example.Visit": true}

// deserActivity is a polymorphic binder: "@class" names the class to build.
func deserActivity(w http.ResponseWriter, r *http.Request) {
	b, ok := deserCookieBytes(r, "activity")
	var doc map[string]any
	if !ok || json.Unmarshal(b, &doc) != nil {
		deserText(w, 200, "Deserialization failed")
		return
	}
	cls, _ := doc["@class"].(string)
	if !deserActivityKnown[cls] {
		deserText(w, 200, "Deserialization failed")
		return
	}
	deserText(w, 200, "Deserialized an unexpected type: "+cls)
}

// deserSafeActivity verifies an HMAC over the JSON before parsing a byte of it.
func deserSafeActivity(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("activity")
	if err != nil {
		deserText(w, 200, "Visit a section to continue")
		return
	}
	body, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		deserText(w, 200, "Payload does not contain a signature")
		return
	}
	if !hmac.Equal([]byte(sig), []byte(deserSign(body))) {
		deserText(w, 200, "Signature mismatch")
		return
	}
	deserText(w, 200, "Last visited section: home")
}

// deserPrefs binds base64 JSON to one fixed type, unknown members refused, with no signature.
func deserPrefs(read func(*http.Request) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := read(r)
		var b []byte
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if d, err := enc.DecodeString(v); err == nil {
				b = d
				break
			}
		}
		var prefs struct {
			Theme string `json:"theme"`
		}
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if b == nil || dec.Decode(&prefs) != nil {
			deserText(w, 200, "Deserialization failed: Failed to deserialize payload")
			return
		}
		theme := prefs.Theme
		if theme == "" {
			theme = "null"
		}
		deserText(w, 200, "Theme: "+theme+", notifications off.")
	}
}
