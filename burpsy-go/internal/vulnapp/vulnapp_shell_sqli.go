package vulnapp

// The SQL-error-versus-shell-error pair (burpsy-react-ui-j1mk.40).
//
// A quote that unbalances a string literal produces "unterminated quoted string" from two very
// different interpreters: PostgreSQL, and a POSIX shell (dash: `sh: 1: Syntax error: Unterminated
// quoted string`). In both, the doubled quote repairs the error. A scanner that reads the wording
// alone reports SQL injection on a command wrapper that has no database behind it, which is what a
// full OWASP VulnerableApp run did on every one of its OS-command levels.
//
//   - /ij/net/hosts concatenates its value into a PostgreSQL string literal and relays the
//     database's own error: SQL injection, proven by the same wording a shell uses.
//   - /ij/net/ping simulates `sh -c "ping -c 2 " + host`, dash-style: quote parsing, word
//     splitting, the `;`/`&&`/`||`/`|`/`&` operators, `not found` for every other command, and a
//     ping whose reply timings and latency vary on every request. It is the SQL row's safe twin:
//     there is no SQL anywhere in it. Nothing is executed; no process is spawned, no name is
//     resolved, and the latency is a bounded sleep.
//
// Both parse the value the way their interpreter would. Neither recognises any payload's spelling.

import (
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// pgStringLiteral reads a PostgreSQL single-quoted literal from s, which starts just after the
// opening quote: `”` is an escaped quote and a lone `'` ends the literal. ok is false when the
// input ends inside the literal.
func pgStringLiteral(s string) (literal, rest string, ok bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\'' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 < len(s) && s[i+1] == '\'' {
			b.WriteByte('\'')
			i++
			continue
		}
		return b.String(), s[i+1:], true
	}
	return b.String(), "", false
}

// hostByName runs `SELECT addr FROM hosts WHERE name = '<name>'` with the name concatenated, the
// way a debug build relays the database's errors.
func hostByName(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	name := r.URL.Query().Get("name")
	statement := "SELECT addr FROM hosts WHERE name = '" + name + "'"
	literal, rest, ok := pgStringLiteral(name + "'")
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		at := statement[strings.LastIndex(statement, "'"):]
		fmt.Fprintf(w, "host lookup failed: ERROR:  unterminated quoted string at or near %q\nLINE 1: %s\n", at, statement)
		return
	}
	if c := strings.Index(rest, "--"); c >= 0 {
		rest = rest[:c]
	}
	if rest = strings.TrimSpace(rest); rest != "" {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "host lookup failed: ERROR:  syntax error at or near %q\nLINE 1: %s\n", strings.Fields(rest)[0], statement)
		return
	}
	if literal == "gateway" {
		fmt.Fprint(w, "gateway 10.0.0.1")
		return
	}
	fmt.Fprint(w, "no such host")
}

// shellCommand is one simple command and the operator that joins it to the previous one.
type shellCommand struct {
	op    string // "", ";", "&", "&&", "||", "|"
	words []string
}

// parseDashScript tokenises a script the way dash does for the subset that matters here: single
// and double quotes (removed once closed), whitespace word splitting, the list operators, and
// parentheses as syntax. diag is dash's own diagnostic when the script does not parse.
func parseDashScript(script string) (cmds []shellCommand, diag string) {
	cur := shellCommand{}
	var word strings.Builder
	inWord := false
	flushWord := func() {
		if inWord {
			cur.words = append(cur.words, word.String())
			word.Reset()
			inWord = false
		}
	}
	endCommand := func(op string) string {
		flushWord()
		if len(cur.words) == 0 {
			return fmt.Sprintf("sh: 1: Syntax error: %q unexpected", op)
		}
		cmds = append(cmds, cur)
		cur = shellCommand{op: op}
		return ""
	}
	for i := 0; i < len(script); i++ {
		c := script[i]
		switch c {
		case '\'', '"':
			end := strings.IndexByte(script[i+1:], c)
			if end < 0 {
				return nil, "sh: 1: Syntax error: Unterminated quoted string"
			}
			word.WriteString(script[i+1 : i+1+end])
			inWord = true
			i += end + 1
		case ' ', '\t':
			flushWord()
		case '(', ')':
			return nil, fmt.Sprintf("sh: 1: Syntax error: %q unexpected", string(c))
		case ';', '&', '|':
			op := string(c)
			if (c == '&' || c == '|') && i+1 < len(script) && script[i+1] == c {
				op += string(c)
				i++
			}
			if d := endCommand(op); d != "" {
				return nil, d
			}
		default:
			word.WriteByte(c)
			inWord = true
		}
	}
	flushWord()
	if len(cur.words) == 0 {
		if cur.op == "&&" || cur.op == "||" || cur.op == "|" {
			return nil, "sh: 1: Syntax error: end of file unexpected"
		}
		return cmds, ""
	}
	return append(cmds, cur), ""
}

// pingHostName is what ping will try to resolve rather than reject outright.
var pingHostName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*$`)

// simulatedPing is `ping -c 2 <args>`: its output and exit status. Reply timings are random, as a
// real ping's are, so no two responses to the same request are byte-identical.
func simulatedPing(args []string, rnd *rand.Rand) (string, int) {
	var hosts []string
	for i := 0; i < len(args); i++ {
		if args[i] == "-c" && i+1 < len(args) {
			i++
			continue
		}
		hosts = append(hosts, args[i])
	}
	switch {
	case len(hosts) == 0:
		return "ping: usage error: Destination address required\n", 2
	case len(hosts) > 1:
		return "ping: usage error: Only one destination address allowed\n", 2
	}
	host := hosts[0]
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		var b strings.Builder
		fmt.Fprintf(&b, "PING %s (%s) 56(84) bytes of data.\n", host, host)
		total := 0.0
		for seq := 1; seq <= 2; seq++ {
			rtt := 0.02 + rnd.Float64()*0.9
			total += rtt
			fmt.Fprintf(&b, "64 bytes from %s: icmp_seq=%d ttl=64 time=%.3f ms\n", host, seq, rtt)
		}
		fmt.Fprintf(&b, "\n--- %s ping statistics ---\n2 packets transmitted, 2 received, 0%% packet loss, time %dms\n",
			host, 1000+rnd.Intn(5))
		fmt.Fprintf(&b, "rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", total/3, total/2, total, total/5)
		return b.String(), 0
	}
	if pingHostName.MatchString(host) {
		return fmt.Sprintf("ping: %s: Temporary failure in name resolution\n", host), 2
	}
	return fmt.Sprintf("ping: %s: Name or service not known\n", host), 2
}

// pingThroughShell is the shell-wrapped ping: the value is appended to `ping -c 2 ` and the whole
// line is handed to a (simulated) `sh -c`. Every command but ping is `not found`; nothing runs.
func pingThroughShell(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	// A real ping's wall time varies with the network; a short random latency keeps the timing
	// baseline honest without costing the suite seconds.
	time.Sleep(time.Duration(20+rnd.Intn(100)) * time.Millisecond)

	var out strings.Builder
	cmds, diag := parseDashScript("ping -c 2 " + r.URL.Query().Get("host"))
	if diag != "" {
		out.WriteString(diag + "\n")
	}
	status := 0
	for _, c := range cmds {
		if (c.op == "&&" && status != 0) || (c.op == "||" && status == 0) {
			continue
		}
		if c.words[0] == "ping" {
			var text string
			text, status = simulatedPing(c.words[1:], rnd)
			out.WriteString(text)
			continue
		}
		fmt.Fprintf(&out, "sh: 1: %s: not found\n", c.words[0])
		status = 127
	}
	fmt.Fprintf(w, "{\"content\":%s,\"isValid\":true}", jsonString(out.String()))
}

// jsonString quotes s as a JSON string, escaping what a JSON encoder would.
func jsonString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`, "<", `<`, ">", `>`, "&", `&`)
	return `"` + r.Replace(s) + `"`
}
