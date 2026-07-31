package intruder

import (
	"context"
	"fmt"
	"net"
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
type AttackConfig struct {
	AttackType    AttackType
	MaxConcurrency int
	Timeout       time.Duration
	FollowRedirects bool
}

// AttackResult represents the result of a single payload attempt.
type AttackResult struct {
	Payload     string
	StatusCode  int
	Length      int
	Time        time.Duration
	Words       int
	Lines       int
	Diff        int
	Error       error
}

// AttackProgress represents the current progress of an attack.
type AttackProgress struct {
	Total       int
	Completed   int
	Errors      int
	StartTime   time.Time
	Status      string // "running", "paused", "completed", "stopped"
}

// Intruder handles payload-based attacks.
type Intruder struct {
	logger     *zap.Logger
	config     *AttackConfig
	results    []*AttackResult
	resultsMu  sync.RWMutex
	progress   AttackProgress
	progressMu sync.RWMutex
}

// NewIntruder creates a new intruder instance.
func NewIntruder(logger *zap.Logger) *Intruder {
	return &Intruder{
		logger: logger,
		config: &AttackConfig{
			MaxConcurrency: 10,
			Timeout:        10 * time.Second,
			FollowRedirects: true,
		},
		results: make([]*AttackResult, 0),
	}
}

// WithConfig sets the attack configuration.
func (i *Intruder) WithConfig(config *AttackConfig) *Intruder {
	i.config = config
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

	i.progressMu.Lock()
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
		
		sem := make(chan struct{}, i.config.MaxConcurrency)
		var wg sync.WaitGroup

		for idx, payload := range payloads {
			select {
			case <-ctx.Done():
				i.setProgressStatus("stopped")
				return
			default:
			}

			wg.Add(1)
			go func(index int, p string) {
				defer wg.Done()

				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					i.setProgressStatus("stopped")
					return
				}

				// Build request with payload
				modifiedRequest := i.injectPayload(baseRequest, positions, p)

				// Send request
				result := i.sendAttack(ctx, modifiedRequest, host, port, tls)
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
				case <-ctx.Done():
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
func (i *Intruder) sendAttack(ctx context.Context, request string, host string, port uint16, tls bool) *AttackResult {
	startTime := time.Now()
	result := &AttackResult{}

	// Connect to target
	network := "tcp"
	if tls {
		network = "tcp" // Would use tls.Dial in real implementation
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout(network, addr, i.config.Timeout)
	if err != nil {
		result.Error = err
		result.Time = time.Since(startTime)
		return result
	}
	defer conn.Close()

	// Set deadline
	conn.SetDeadline(time.Now().Add(i.config.Timeout))

	// Send request
	_, err = conn.Write([]byte(request))
	if err != nil {
		result.Error = err
		result.Time = time.Since(startTime)
		return result
	}

	// Read response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		result.Error = err
		result.Time = time.Since(startTime)
		return result
	}

	// Parse status code (simplified)
	response := string(buf[:n])
	lines := strings.Split(response, "\n")
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			fmt.Sscanf(parts[1], "%d", &result.StatusCode)
		}
	}

	result.Length = n
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

// Stop stops the current attack.
func (i *Intruder) Stop() {
	i.setProgressStatus("stopped")
}

// PayloadGenerator generates payloads for attacks.
type PayloadGenerator struct{}

// NewPayloadGenerator creates a new payload generator.
func NewPayloadGenerator() *PayloadGenerator {
	return &PayloadGenerator{}
}

// GenerateNumbers generates numeric payloads.
func (pg *PayloadGenerator) GenerateNumbers(start, end int) []string {
	payloads := make([]string, end-start+1)
	for i := start; i <= end; i++ {
		payloads[i-start] = fmt.Sprintf("%d", i)
	}
	return payloads
}

// GenerateFromFile loads payloads from a file.
func (pg *PayloadGenerator) GenerateFromFile(filename string) ([]string, error) {
	// Would read file in real implementation
	return []string{}, nil
}

// GenerateCustom generates payloads from a custom list.
func (pg *PayloadGenerator) GenerateCustom(payloads []string) []string {
	return payloads
}
