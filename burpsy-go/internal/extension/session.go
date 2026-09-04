package extension

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// session is one running plugin process and the conversation with it.
//
// It owns four goroutines' worth of work — a stdout reader, a stderr reader, a
// reaper and whatever is waiting on a call — and every one of them is bounded: the
// readers by maxMessageBytes per line and by the console's own ring, the reaper by
// the process it waits on, a call by its context. Nothing here retains a message
// after it has been dispatched.
type session struct {
	name    string
	cmd     *exec.Cmd
	console *console

	maxMessageBytes int

	// writeMu serialises writes to the child's stdin. One JSON value per line is
	// only a framing if two goroutines cannot interleave halves of two lines.
	writeMu sync.Mutex
	stdin   io.WriteCloser

	mu      sync.Mutex
	nextID  int64
	pending map[int64]chan rpcMessage
	// closed is set once the transport is gone, so a call started after the plugin
	// exited fails immediately instead of waiting out its timeout on a channel
	// nothing will ever write to.
	closed bool
	// closeReason is what to tell a caller whose call cannot be completed.
	closeReason string

	// done closes when the stdout reader has finished, which is the point after
	// which no reply can arrive. Separate from exited because a plugin can close
	// its stdout and keep running.
	done chan struct{}
	// exited closes when the child has been reaped and exit holds how it ended.
	exited chan struct{}
	exit   ExitInfo

	// protocolErrors counts stdout lines that were not JSON-RPC messages, plus
	// notifications naming a method this host does not implement. Atomic because
	// the reader increments it while the API serialises the count.
	protocolErrors atomic.Int64
}

// PluginSpec is one allowlist entry: the executable, and how it is launched.
type PluginSpec struct {
	// Path is the executable. It is run directly, with no shell, so an argument
	// containing shell metacharacters is data — the same rule as
	// scanner.execToolRunner.Run.
	Path string
	// Args are extra arguments. The -plugins flag never sets any: a plugin that
	// needs an interpreter should be an executable script with a shebang, because
	// splitting a flag value into argv is a small shell and this package does not
	// want one. Present so a caller inside this process (a test, most obviously)
	// can launch a plugin that needs them.
	Args []string
	// Env are extra KEY=VALUE pairs for the child, on top of the four pass-through
	// variables below. Also never set by the flag.
	Env []string
}

// passedEnv is the host environment a plugin inherits, and the list is short on
// purpose.
//
// A plugin is code the operator explicitly allowlisted, so this is not a sandbox
// and does not pretend to be one. But an operator's shell environment routinely
// holds credentials for services that have nothing to do with the engagement, and
// a plugin has no reason to read them; inheriting the whole environment would hand
// every plugin all of them by default. These four are what a language runtime
// needs to start at all.
var passedEnv = []string{"PATH", "HOME", "LANG", "TMPDIR"}

func childEnv(name string, extra []string) []string {
	env := make([]string, 0, len(passedEnv)+len(extra)+2)
	for _, key := range passedEnv {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	env = append(env,
		"BURPSY_PLUGIN_NAME="+name,
		fmt.Sprintf("BURPSY_PLUGIN_PROTOCOL=%d", ProtocolVersion),
	)
	return append(env, extra...)
}

// spawn starts the child and begins reading both of its streams.
//
// ctx bounds the process for its whole life, not just the launch: it is the host's
// context, so closing the host kills every plugin it started rather than leaving
// orphans behind a dead server.
func spawn(ctx context.Context, name string, spec PluginSpec, con *console, maxMessageBytes int) (*session, error) {
	if spec.Path == "" {
		return nil, fmt.Errorf("plugin %q maps to an empty path", name)
	}
	cmd := exec.CommandContext(ctx, spec.Path, spec.Args...)
	cmd.Env = childEnv(name, spec.Env)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("plugin %q: stdin: %w", name, err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("plugin %q: stdout: %w", name, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("plugin %q: stderr: %w", name, err)
	}
	if err := cmd.Start(); err != nil {
		// The launch failure, verbatim. "no such file or directory" against the
		// allowlisted path is the single most likely first-run problem and the
		// operator needs the path in the message, not a wrapped "load failed".
		return nil, fmt.Errorf("plugin %q: cannot start %s: %w", name, spec.Path, err)
	}
	if maxMessageBytes <= 0 {
		maxMessageBytes = DefaultMaxMessageBytes
	}
	s := &session{
		name:            name,
		cmd:             cmd,
		console:         con,
		maxMessageBytes: maxMessageBytes,
		stdin:           stdin,
		pending:         make(map[int64]chan rpcMessage),
		done:            make(chan struct{}),
		exited:          make(chan struct{}),
	}
	var readers sync.WaitGroup
	readers.Add(2)
	go func() { defer readers.Done(); s.readStdout(stdout) }()
	go func() { defer readers.Done(); s.readStderr(stderr) }()
	// One reaper, and only one: os/exec documents that calling Wait before the
	// pipe reads have finished is incorrect, because Wait closes the pipes. So the
	// reaper waits on the readers first, and nothing else in this package calls
	// Wait — stop() waits on s.exited instead.
	go func() {
		readers.Wait()
		s.exit = exitInfo(cmd.Wait())
		close(s.exited)
	}()
	return s, nil
}

// readStdout is the whole inbound protocol.
func (s *session) readStdout(r io.Reader) {
	defer close(s.done)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64<<10), s.maxMessageBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var msg rpcMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			// Recorded, not dropped. A plugin author's first mistake is printing to
			// stdout; a host that silently swallowed it would leave them with a plugin
			// that loads, does nothing, and reports nothing about why.
			s.protocolErrors.Add(1)
			s.console.append(StreamError, SourceProtocol, "not a JSON-RPC message: "+line)
			continue
		}
		s.dispatch(msg)
	}
	err := scanner.Err()
	reason := "the plugin's stdout closed"
	switch {
	case errors.Is(err, bufio.ErrTooLong):
		// The session ends rather than resynchronising. After a truncated read the
		// next byte could be anywhere inside a message, so continuing would mean
		// guessing where the next one starts — and a guess here silently corrupts
		// every subsequent reply.
		s.protocolErrors.Add(1)
		reason = fmt.Sprintf("a message exceeded the %d-byte bound; the stream cannot be resynchronised", s.maxMessageBytes)
		s.console.append(StreamError, SourceProtocol, reason)
	case err != nil:
		reason = "reading the plugin's stdout failed: " + err.Error()
		s.console.append(StreamError, SourceProtocol, reason)
	}
	s.fail(reason)
}

// dispatch routes one parsed message: a reply to a waiting call, or something the
// plugin originated.
func (s *session) dispatch(msg rpcMessage) {
	// A reply carries an id and no method. Routed first because it is the common case.
	if msg.Method == "" && msg.ID != nil {
		var id int64
		if err := json.Unmarshal(*msg.ID, &id); err != nil {
			s.protocolErrors.Add(1)
			s.console.append(StreamError, SourceProtocol,
				"reply carried an id this host never issued: "+string(*msg.ID))
			return
		}
		s.mu.Lock()
		waiter, ok := s.pending[id]
		delete(s.pending, id)
		s.mu.Unlock()
		if !ok {
			// A reply to a call that already timed out, or an id out of thin air.
			// Counted rather than ignored: it is the shape of a plugin that answers
			// late, which an operator debugging a timeout needs to know.
			s.protocolErrors.Add(1)
			s.console.append(StreamError, SourceProtocol,
				fmt.Sprintf("reply for request %d, which is not outstanding", id))
			return
		}
		// Buffered channel with exactly one slot, and this is the only send: the
		// waiter has already been removed from the map, so no second reply can
		// reach it and this cannot block.
		waiter <- msg
		return
	}
	if handler, ok := inbound[msg.Method]; ok {
		handler(s, msg)
		return
	}
	// A request (it has an id) gets a JSON-RPC error so the plugin's own await
	// resolves. A notification gets counted, because there is nobody to tell.
	if msg.ID != nil {
		s.reply(msg.ID, nil, &rpcError{Code: codeMethodNotFound, Message: "burpsy implements no method " + msg.Method})
	}
	s.protocolErrors.Add(1)
	s.console.append(StreamError, SourceProtocol, "unimplemented method from plugin: "+msg.Method)
}

// inbound is every method a plugin may send the host.
//
// A map rather than a switch because the method-set test compares its key set
// against the PluginToHost entries of MethodSpecs. A switch would be the same code
// with nothing checkable about it.
var inbound = map[string]func(*session, rpcMessage){
	"log": func(s *session, msg rpcMessage) {
		var params LogParams
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			s.protocolErrors.Add(1)
			s.console.append(StreamError, SourceProtocol, "log notification with unreadable params: "+err.Error())
			return
		}
		stream := StreamOutput
		if params.Stream == StreamError {
			stream = StreamError
		}
		s.console.append(stream, SourcePlugin, params.Message)
		if msg.ID != nil {
			// Declared a notification, sent as a request. Answered so the plugin does
			// not hang waiting, and the mismatch is recorded.
			s.reply(msg.ID, json.RawMessage(`{}`), nil)
			s.protocolErrors.Add(1)
			s.console.append(StreamError, SourceProtocol, "log is a notification; it was sent as a request")
		}
	},
}

func (s *session) readStderr(r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 8<<10), s.maxMessageBytes)
	for scanner.Scan() {
		s.console.append(StreamError, SourceStderr, scanner.Text())
	}
}

// call sends a request and waits for its reply.
//
// The method name is a string literal at every call site, and that is a
// constraint rather than a habit: Test_the_documented_method_set_is_the_dispatched_method_set
// reads those literals out of this package's source and compares them to
// MethodSpecs, so a method invented here without a spec fails the tests.
// internal/web/route_manifest_test.go refuses non-literal route patterns for
// exactly the same reason.
func (s *session) call(ctx context.Context, method string, params any, out any) error {
	encoded, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("%s: encoding params: %w", method, err)
	}
	s.mu.Lock()
	if s.closed {
		reason := s.closeReason
		s.mu.Unlock()
		return fmt.Errorf("%s: %s", method, reason)
	}
	s.nextID++
	id := s.nextID
	waiter := make(chan rpcMessage, 1)
	s.pending[id] = waiter
	s.mu.Unlock()

	idBytes := json.RawMessage(fmt.Sprintf("%d", id))
	if err := s.write(rpcMessage{JSONRPC: "2.0", ID: &idBytes, Method: method, Params: encoded}); err != nil {
		s.forget(id)
		return fmt.Errorf("%s: %w", method, err)
	}

	select {
	case msg := <-waiter:
		if msg.Error != nil {
			return fmt.Errorf("%s: plugin reported error %d: %s", method, msg.Error.Code, msg.Error.Message)
		}
		if out == nil {
			return nil
		}
		if len(msg.Result) == 0 {
			// A reply with neither result nor error is not a valid JSON-RPC response.
			// Refused rather than decoded as a zero value, which would look like a
			// plugin that answered with empty fields.
			return fmt.Errorf("%s: reply carried neither a result nor an error", method)
		}
		if err := json.Unmarshal(msg.Result, out); err != nil {
			return fmt.Errorf("%s: unreadable result: %w", method, err)
		}
		return nil
	case <-s.done:
		s.forget(id)
		return fmt.Errorf("%s: %s", method, s.reasonOrDefault("the plugin exited before answering"))
	case <-ctx.Done():
		s.forget(id)
		return fmt.Errorf("%s: %w", method, ctx.Err())
	}
}

func (s *session) reply(id *json.RawMessage, result json.RawMessage, rpcErr *rpcError) {
	if err := s.write(rpcMessage{JSONRPC: "2.0", ID: id, Result: result, Error: rpcErr}); err != nil {
		s.console.append(StreamError, SourceHost, "could not answer the plugin: "+err.Error())
	}
}

func (s *session) write(msg rpcMessage) error {
	encoded, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if len(encoded)+1 > s.maxMessageBytes {
		// Refused on the way out for the same reason it is refused on the way in: a
		// plugin reading with a line bound would see a truncated line and desync.
		return fmt.Errorf("message of %d bytes exceeds the %d-byte bound", len(encoded)+1, s.maxMessageBytes)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err = s.stdin.Write(append(encoded, '\n'))
	return err
}

func (s *session) forget(id int64) {
	s.mu.Lock()
	delete(s.pending, id)
	s.mu.Unlock()
}

// fail marks the transport gone. Waiters are not signalled here: every call also
// selects on s.done, which the stdout reader closes immediately after calling
// this, so closing their channels as well would race that send.
func (s *session) fail(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.closeReason == "" {
		s.closeReason = reason
	}
	s.pending = map[int64]chan rpcMessage{}
}

func (s *session) reasonOrDefault(fallback string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closeReason != "" {
		return s.closeReason
	}
	return fallback
}

// stop ends the session: ask, then close stdin, then kill.
//
// Three escalating steps because a plugin holding an open file or a network
// connection deserves the chance to close it, and a plugin that ignores the ask
// must not keep the host waiting. Each step is bounded by grace, and the whole
// thing returns only once the child has actually been reaped — an unload that
// reported success while the process was still running would be a lie the next
// load would trip over.
func (s *session) stop(grace time.Duration) ExitInfo {
	if grace <= 0 {
		grace = DefaultShutdownGrace
	}
	ctx, cancel := context.WithTimeout(context.Background(), grace)
	// The error is deliberately ignored: a plugin that has already died cannot
	// answer, and that is not a failure of the unload.
	_ = s.call(ctx, "shutdown", ShutdownParams{Reason: "operator unloaded the plugin"}, nil)
	cancel()

	// Closing stdin is the second ask: a plugin whose read loop ends on EOF exits
	// here without needing to implement `shutdown` at all.
	_ = s.stdin.Close()

	select {
	case <-s.exited:
	case <-time.After(grace):
		if s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
		<-s.exited
	}
	return s.exit
}

// exitInfo renders what cmd.Wait reported.
func exitInfo(err error) ExitInfo {
	info := ExitInfo{AtMs: time.Now().UnixMilli()}
	if err == nil {
		return info
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		info.Code = exitErr.ExitCode()
		if info.Code == -1 {
			// ExitCode is -1 when a signal ended the process, and the code alone
			// cannot say which. ProcessState renders it ("signal: killed"), which is
			// the part that distinguishes an aborted runtime from exit(1).
			info.Signal = exitErr.String()
		}
		return info
	}
	info.Code = -1
	info.Detail = err.Error()
	return info
}
