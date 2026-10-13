package intruder

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// AttackType represents the type of intruder attack.
type AttackType int

const (
	AttackSniper AttackType = iota
	AttackBatteringRam
	AttackPitchfork
	AttackClusterBomb
)

// AttackConfig holds configuration for an intruder attack.
//
// There is deliberately no FollowRedirects knob. There used to be one, set to true at construction
// and read by nothing — the attack sends through the sender's raw path, which does not follow
// redirects at all. A config field that no code consults is worse than a missing feature: it reads as
// a promise, and the next person to need redirect-following would have set it, observed no redirects
// followed, and gone looking for the bug somewhere else entirely. If an attack ever needs to follow a
// redirect it must do so per hop, re-authorising the new authority through the scope chokepoint,
// because a 30x is exactly how a target steers an attack somewhere nobody authorised.
type AttackConfig struct {
	AttackType     AttackType
	MaxConcurrency int
	Timeout        time.Duration
}

// AttackResult represents the result of a single payload attempt.
type AttackResult struct {
	Payload    string
	StatusCode int
	Length     int
	Time       time.Duration
	Words      int
	Lines      int
	Diff       int
	Error      error
}

// AttackProgress represents the current progress of an attack.
type AttackProgress struct {
	Total     int
	Completed int
	Errors    int
	StartTime time.Time
	Status    string // "running", "paused", "completed", "stopped"
}

// Intruder handles payload-based attacks.
type Intruder struct {
	logger     *zap.Logger
	config     *AttackConfig
	results    []*AttackResult
	resultsMu  sync.RWMutex
	progress   AttackProgress
	progressMu sync.RWMutex
	// runCancel cancels the context of the in-flight Run, so Stop() can halt
	// an attack without depending on the caller to cancel the context it
	// passed in. Guarded by progressMu (set/cleared alongside the Status).
	runCancel context.CancelFunc
	// send is the only way out of this engine. Nil means the engine cannot send at all — see
	// sendAttack for why that is a refusal rather than a fallback to dialling directly.
	send AttackSendFunc
}

// AttackSendFunc puts one spliced attack request on the wire and returns the raw response.
//
// The seam exists so this package never learns about scope: the caller supplies a function closed
// over a sender.AuthorisedSender bound to the target's own authority, and the scope decision happens
// there, on the bytes, before the dial. A payload spliced into a path position rewrites the request
// line, so authorising the named target once at the start of a run would be checking something other
// than what goes out.
type AttackSendFunc func(ctx context.Context, host string, port uint16, tls bool, raw []byte) ([]byte, error)

// errNoAuthorisedSender is returned for every attempt when no send function was supplied. A named
// error so a caller can tell "this engine was never wired" from a transport failure against a host.
var errNoAuthorisedSender = errors.New(
	"intruder: no authorised sender was supplied, so nothing can be sent; " +
		"wire one with WithSend so the engagement scope decides about each request")

// WithSend supplies the authorised egress path. An engine without one refuses to send.
func (i *Intruder) WithSend(fn AttackSendFunc) *Intruder {
	i.send = fn
	return i
}

// NewIntruder creates a new intruder instance.
func NewIntruder(logger *zap.Logger) *Intruder {
	return &Intruder{
		logger: logger,
		config: &AttackConfig{
			MaxConcurrency: 10,
			Timeout:        10 * time.Second,
		},
		results: make([]*AttackResult, 0),
	}
}

// WithConfig sets the attack configuration. A nil config is ignored so the
// caller cannot nil-deref i.config on the next send.
func (i *Intruder) WithConfig(config *AttackConfig) *Intruder {
	if config != nil {
		i.config = config
	}
	return i
}

// AttackPayload represents a payload with position markers.
type AttackPayload struct {
	Position int
	Value    string
}

// Run executes an intruder attack.
func (i *Intruder) Run(ctx context.Context, baseRequest string, host string, port uint16, tls bool, payloads []string, positions []int) (<-chan *AttackResult, error) {
	resultsCh := make(chan *AttackResult, 100)

	// Derive a cancellable context so Stop() can halt this run even when the
	// caller does not cancel its own ctx (the CLI passes a timeout context it
	// does not cancel on Stop). Stored on the struct under progressMu.
	runCtx, runCancel := context.WithCancel(ctx)
	i.progressMu.Lock()
	i.runCancel = runCancel
	i.progress = AttackProgress{
		Total:     len(payloads),
		Completed: 0,
		Errors:    0,
		StartTime: time.Now(),
		Status:    "running",
	}
	i.progressMu.Unlock()

	go func() {
		defer close(resultsCh)
		// finish records the final status and clears the cancel handle under one lock, so a later
		// Stop is a no-op rather than cancelling a dead context or relabelling the finished run, and
		// no Stop can slip in between the status write and the handle clear.
		finish := func() {
			i.progressMu.Lock()
			// Stop cancels runCtx while holding progressMu, so reading runCtx.Err() under the same
			// lock cannot miss a Stop that already happened. A run that dispatched every payload
			// but was cancelled while workers were still in flight ended because of the Stop, not
			// because the plan was exhausted: their sends returned the cancellation, not a
			// response. Reporting it "completed" would overwrite the "stopped" Stop set.
			status := "completed"
			if runCtx.Err() != nil {
				status = "stopped"
			}
			i.progress.Status = status
			i.runCancel = nil
			i.progressMu.Unlock()
			runCancel() // release the derived context's resources
		}

		// Bound concurrency: one permit per in-flight worker, acquired in the
		// driver loop *before* a worker is spawned. Spawning a goroutine per
		// payload and acquiring the permit inside it would create N goroutines
		// for N payloads (≈4–8 KB stack each → ~1 GB for 200k payloads), the
		// exact memory failure this project's engine.go exists to avoid.
		maxConc := i.config.MaxConcurrency
		if maxConc <= 0 {
			maxConc = 1
		}
		sem := make(chan struct{}, maxConc)
		var wg sync.WaitGroup

		for idx, payload := range payloads {
			// Acquire the permit before spawning, honouring cancellation while
			// we wait. A worker is never started without a slot reserved, so the
			// live-goroutine count is bounded by maxConc.
			select {
			case <-runCtx.Done():
				i.setProgressStatus("stopped")
				// Wait for in-flight workers before closing the channel: a worker
				// that reaches `resultsCh <- result` after we return would panic
				// with "send on closed channel". wg.Wait guarantees none remain.
				wg.Wait()
				finish()
				return
			case sem <- struct{}{}:
			}

			wg.Add(1)
			go func(index int, p string) {
				defer wg.Done()
				defer func() { <-sem }()

				// Build request with payload
				modifiedRequest := i.injectPayload(baseRequest, positions, p)

				// Send request
				result := i.sendAttack(runCtx, modifiedRequest, host, port, tls)
				result.Payload = p

				// Store result
				i.resultsMu.Lock()
				i.results = append(i.results, result)
				i.resultsMu.Unlock()

				// Update progress
				i.incrementProgress(result.Error != nil)

				// Send to channel
				select {
				case resultsCh <- result:
				case <-runCtx.Done():
				}
			}(idx, payload)
		}

		wg.Wait()
		finish()
	}()

	return resultsCh, nil
}

// injectPayload replaces markers in the request with the payload.
func (i *Intruder) injectPayload(baseRequest string, positions []int, payload string) string {
	if len(positions) == 0 {
		// Replace §markers§ if no explicit positions
		parts := strings.Split(baseRequest, "§")
		if len(parts) > 1 {
			// Replace odd-indexed parts (the markers)
			for j := 1; j < len(parts); j += 2 {
				parts[j] = payload
			}
			return strings.Join(parts, "")
		}
		return baseRequest
	}

	// Replace at byte positions
	requestBytes := []byte(baseRequest)
	// Simple replacement - would need more sophisticated handling in production
	result := string(requestBytes)
	for _, pos := range positions {
		if pos < len(result) {
			// Insert payload at position
			result = result[:pos] + payload + result[pos:]
		}
	}
	return result
}

// sendAttack sends a single attack request through the injected authorised sender.
//
// It used to dial the target itself — tls.DialWithDialer with InsecureSkipVerify, or a bare
// net.DialTimeout — so it never entered internal/sender and no scope check of any kind ran on the
// bytes it put on the wire. `burpsy -scope-include app.example.com intruder run -target
// internal-admin.corp:8080 ...` delivered the whole attack volume to a host the operator's own scope
// excluded, with TLS unverified, and reported it as an ordinary attack. HARD-03 names every
// request-originating surface; this was one, and it was the last unguarded one.
//
// The send is injected rather than constructed here so this package keeps knowing nothing about
// scope — the same trait-seam shape session.MacroStepRunner uses. The gate lives at the call site,
// which is where the engagement scope is known. TLS verification now comes from the shared sender's
// config instead of being hardcoded off.
func (i *Intruder) sendAttack(ctx context.Context, request string, host string, port uint16, useTLS bool) *AttackResult {
	startTime := time.Now()
	result := &AttackResult{}

	if i.send == nil {
		// Fail closed. An attack engine with no authorised way out must refuse rather than fall back
		// to dialling directly, which is precisely the defect this replaced.
		result.Error = errNoAuthorisedSender
		result.Time = time.Since(startTime)
		return result
	}
	resp, err := i.send(ctx, host, port, useTLS, []byte(request))
	if err != nil {
		result.Error = err
		result.Time = time.Since(startTime)
		return result
	}

	// Parse status code
	response := string(resp)
	lines := strings.Split(response, "\n")
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			fmt.Sscanf(parts[1], "%d", &result.StatusCode)
		}
	}

	result.Length = len(resp)
	result.Lines = strings.Count(response, "\n")
	result.Words = len(strings.Fields(response))
	result.Time = time.Since(startTime)

	return result
}

func (i *Intruder) incrementProgress(isError bool) {
	i.progressMu.Lock()
	defer i.progressMu.Unlock()
	i.progress.Completed++
	if isError {
		i.progress.Errors++
	}
}

func (i *Intruder) setProgressStatus(status string) {
	i.progressMu.Lock()
	defer i.progressMu.Unlock()
	i.progress.Status = status
}

// GetProgress returns the current attack progress.
func (i *Intruder) GetProgress() AttackProgress {
	i.progressMu.RLock()
	defer i.progressMu.RUnlock()
	return i.progress
}

// GetResults returns all attack results.
func (i *Intruder) GetResults() []*AttackResult {
	i.resultsMu.RLock()
	defer i.resultsMu.RUnlock()

	result := make([]*AttackResult, len(i.results))
	copy(result, i.results)
	return result
}

// ClearResults clears all results.
func (i *Intruder) ClearResults() {
	i.resultsMu.Lock()
	defer i.resultsMu.Unlock()
	i.results = make([]*AttackResult, 0)
}

// Stop stops the current attack. It cancels the in-flight run's context —
// previously it only set the status string, which left the run blocked on a
// timeout the caller owned and never cancelled. Now the driver's select on
// runCtx.Done() fires, workers drain, and the channel closes cleanly.
//
// With no run in flight it is a no-op: a finished attack keeps the status it ended with, so a late
// Stop cannot relabel a completed attack as stopped.
func (i *Intruder) Stop() {
	i.progressMu.Lock()
	defer i.progressMu.Unlock()
	if i.runCancel == nil {
		return
	}
	i.runCancel()
	i.progress.Status = "stopped"
}
