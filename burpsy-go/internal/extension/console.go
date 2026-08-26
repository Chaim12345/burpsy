package extension

import (
	"sync"
	"time"
)

// Source says who produced a console line, and it is the field that keeps this
// surface honest.
//
// Burp gives an extension an output console and an error console because Montoya
// hands it two PrintStreams. Here stdout is the JSON-RPC transport, so "the
// plugin's output" cannot mean "whatever appeared on stdout" — it has to mean
// "what the plugin deliberately logged". That leaves three other things that can
// end up on a console, and folding them into the plugin's own output would
// attribute the host's words to the plugin: a line the *host* wrote (loaded,
// unloaded, crashed), a line the child wrote to stderr, and a line on stdout
// that was not a JSON-RPC message at all. Each keeps its own source so an
// operator reading the error console can tell "the plugin reported a problem"
// from "the plugin is not speaking the protocol".
type Source string

const (
	// SourcePlugin is a line the plugin sent as a `log` notification.
	SourcePlugin Source = "plugin"
	// SourceStderr is a line the child process wrote to stderr. This is where a
	// runtime's own crash trace lands, which is what makes it worth keeping
	// separate: it is the plugin's failure, but not the plugin's message.
	SourceStderr Source = "stderr"
	// SourceHost is a line this host wrote: a load, an unload, a crash, a refused
	// registration. Attributed to the host so it cannot be read as plugin output.
	SourceHost Source = "host"
	// SourceProtocol is a line that arrived on stdout and was not a JSON-RPC
	// message. Recorded rather than dropped: silently discarding it would make a
	// plugin that prints to stdout look like a plugin that does nothing.
	SourceProtocol Source = "protocol"
)

// Stream is which of the two consoles a line belongs on.
type Stream string

const (
	// StreamOutput is the plugin's output console: what it chose to report.
	StreamOutput Stream = "output"
	// StreamError is the error console: stderr, protocol violations, and the
	// host's own failure notes.
	StreamError Stream = "error"
)

// Line is one console entry.
type Line struct {
	// AtMs is a wall-clock millisecond stamp. Milliseconds rather than a
	// formatted time because the UI formats it, and two renderings of one instant
	// drift.
	AtMs   int64  `json:"at_ms"`
	Stream Stream `json:"stream"`
	Source Source `json:"source"`
	Text   string `json:"text"`
}

// ConsoleView is one plugin's consoles as served, including what was dropped.
//
// Dropped is not a diagnostic afterthought. A console that silently forgets its
// oldest lines and reports only the survivors tells an operator that a plugin
// logged eleven lines when it logged eleven thousand, and the interesting one is
// exactly the one that fell off the front.
type ConsoleView struct {
	Output []Line `json:"output"`
	Error  []Line `json:"error"`
	// OutputDropped and ErrorDropped count lines evicted by the bound, per stream.
	OutputDropped int `json:"output_dropped"`
	ErrorDropped  int `json:"error_dropped"`
	// Truncated counts lines whose text was cut to MaxLineBytes.
	Truncated int `json:"truncated"`
	// Limit is the per-stream line bound in force, so the caller can tell "this
	// plugin logged 200 lines" from "the bound is 200".
	Limit int `json:"limit"`
}

// console is a bounded, separately locked pair of ring buffers.
//
// Its own mutex, deliberately not the plugin's: the stdout reader writes here on
// every log notification, and the load path holds the plugin's lock across a
// handshake that itself produces log lines. One shared lock would deadlock the
// first plugin that logged during initialize.
type console struct {
	mu             sync.Mutex
	maxLines       int
	maxLineBytes   int
	output, errs   []Line
	outDrop, eDrop int
	truncated      int
}

func newConsole(maxLines, maxLineBytes int) *console {
	if maxLines <= 0 {
		maxLines = DefaultMaxConsoleLines
	}
	if maxLineBytes <= 0 {
		maxLineBytes = DefaultMaxConsoleLineBytes
	}
	return &console{maxLines: maxLines, maxLineBytes: maxLineBytes}
}

// append records one line, evicting the oldest when the stream is full.
//
// Oldest-first eviction rather than refusing new lines: a plugin's most recent
// output is what an operator is looking at when something has just gone wrong.
func (c *console) append(stream Stream, source Source, text string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(text) > c.maxLineBytes {
		// Marked in the text as well as counted, because a line that was cut and a
		// line that happened to end there are indistinguishable otherwise.
		text = text[:c.maxLineBytes] + "… [truncated]"
		c.truncated++
	}
	line := Line{AtMs: time.Now().UnixMilli(), Stream: stream, Source: source, Text: text}
	if stream == StreamError {
		c.errs = appendBounded(c.errs, line, c.maxLines, &c.eDrop)
		return
	}
	c.output = appendBounded(c.output, line, c.maxLines, &c.outDrop)
}

func appendBounded(into []Line, line Line, max int, dropped *int) []Line {
	if len(into) < max {
		return append(into, line)
	}
	// Shift by one rather than reallocate: the buffer is at its bound and stays
	// there for the life of a chatty plugin.
	copy(into, into[1:])
	into[len(into)-1] = line
	*dropped++
	return into
}

// view copies both streams. limit <= 0 means every retained line.
func (c *console) view(limit int) ConsoleView {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ConsoleView{
		Output:        tail(c.output, limit),
		Error:         tail(c.errs, limit),
		OutputDropped: c.outDrop,
		ErrorDropped:  c.eDrop,
		Truncated:     c.truncated,
		Limit:         c.maxLines,
	}
}

// counts reports how many lines each stream currently holds, for the list view's
// per-plugin columns without copying the lines themselves.
func (c *console) counts() (output, errs int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.output), len(c.errs)
}

func tail(lines []Line, limit int) []Line {
	if limit > 0 && len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	// A fresh slice every time: the caller marshals this while the reader
	// goroutine may be shifting the ring underneath it.
	out := make([]Line, len(lines))
	copy(out, lines)
	return out
}
