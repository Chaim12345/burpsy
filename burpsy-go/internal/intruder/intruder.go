package intruder

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/httputil"
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
		// Clear the cancel handle on exit so a later Stop is a no-op rather
		// than cancelling a dead context.
		defer func() {
			i.progressMu.Lock()
			i.runCancel = nil
			i.progressMu.Unlock()
		}()

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
		i.setProgressStatus("completed")
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

// sendAttack sends a single attack request.
func (i *Intruder) sendAttack(ctx context.Context, request string, host string, port uint16, useTLS bool) *AttackResult {
	startTime := time.Now()
	result := &AttackResult{}

	// Connect to target
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	var conn net.Conn
	var err error
	if useTLS {
		dialer := &net.Dialer{Timeout: i.config.Timeout}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, // proxy-style scanning of arbitrary targets
		})
	} else {
		conn, err = net.DialTimeout("tcp", addr, i.config.Timeout)
	}
	if err != nil {
		result.Error = err
		result.Time = time.Since(startTime)
		return result
	}
	defer conn.Close()

	// If the caller's context already carries a deadline, honour it; otherwise
	// fall back to the configured per-request timeout.
	deadline := time.Now().Add(i.config.Timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		result.Error = fmt.Errorf("set deadline: %w", err)
		result.Time = time.Since(startTime)
		return result
	}

	// Close the conn when ctx is cancelled, so a blocked Read/Write unblocks
	// instead of waiting out the whole deadline. sendAttack previously ignored
	// ctx entirely, so a Stop()/timeout could not interrupt an in-flight read.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stop:
		}
	}()

	// Send request
	_, err = conn.Write([]byte(request))
	if err != nil {
		result.Error = err
		result.Time = time.Since(startTime)
		return result
	}

	// Read response
	resp, err := httputil.ReadHTTPResponse(conn)
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
func (i *Intruder) Stop() {
	i.progressMu.Lock()
	if i.runCancel != nil {
		i.runCancel()
	}
	i.progress.Status = "stopped"
	i.progressMu.Unlock()
}

// PayloadGenerator generates payloads for attacks.
type PayloadGenerator struct{}

// NewPayloadGenerator creates a new payload generator.
func NewPayloadGenerator() *PayloadGenerator {
	return &PayloadGenerator{}
}

// GenerateNumbers generates numeric payloads from start to end inclusive.
// An inverted range (start > end) yields no payloads rather than panicking in
// make with a negative length.
func (pg *PayloadGenerator) GenerateNumbers(start, end int) []string {
	if end < start {
		return []string{}
	}
	payloads := make([]string, end-start+1)
	for i := start; i <= end; i++ {
		payloads[i-start] = fmt.Sprintf("%d", i)
	}
	return payloads
}

// GenerateFromFile loads payloads from a file, one payload per line.
// Blank lines are skipped; surrounding whitespace is trimmed.
func (pg *PayloadGenerator) GenerateFromFile(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var payloads []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			payloads = append(payloads, line)
		}
	}
	return payloads, nil
}

// GenerateCustom generates payloads from a custom list.
func (pg *PayloadGenerator) GenerateCustom(payloads []string) []string {
	return payloads
}
