package scanner

import (
	"context"
	"fmt"
	"sync"

	"github.com/burpsy-go/burpsy/internal/domexec"
)

// SwitchableBrowsers is the DOM engine as a runtime setting (the live form of -dom): one stable
// provider the scanners hold for their whole life, whose engine the console can set, change or
// remove while the process runs (PUT /api/scanner/dom).
//
// It is a wrapper rather than a re-assignment of ActiveScanner.browsers because that field is read
// without the scanner's lock from every DOM path (checks, confirmation, stored render, crawl); a
// pointer that never changes after wiring keeps those reads race-free, and the swap happens under
// this type's own lock.
//
// Empty, it answers like a scanner with no engine at all: Configured is false, and Browser fails
// with errCapabilityMissing, so a DOM check counts as skipped (not as a target failure) and every
// "is an engine there" question says no.
type SwitchableBrowsers struct {
	mu    sync.RWMutex
	inner BrowserProvider
	label string
}

// NewSwitchableBrowsers builds an empty switch (no engine).
func NewSwitchableBrowsers() *SwitchableBrowsers { return &SwitchableBrowsers{} }

// Set installs p (nil removes the engine) under label, the -dom style value the console reports.
// The engine it replaces is closed after the swap, outside the lock, so a slow Chrome shutdown
// never holds up a check asking for the new one. A check holding a tab of the old browser loses
// it; that is what switching the engine means.
func (s *SwitchableBrowsers) Set(p BrowserProvider, label string) error {
	s.mu.Lock()
	old := s.inner
	s.inner = p
	s.label = label
	if p == nil {
		s.label = ""
	}
	s.mu.Unlock()
	if old != nil && old != p {
		return old.Close()
	}
	return nil
}

// Label is the engine's -dom value, or "" when there is none.
func (s *SwitchableBrowsers) Label() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.label
}

// Configured reports whether an engine is set now. Like DOMCapabilityConfigured it answers from
// configuration alone and never starts a browser.
func (s *SwitchableBrowsers) Configured() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inner != nil
}

func (s *SwitchableBrowsers) Browser(ctx context.Context) (*domexec.Browser, error) {
	s.mu.RLock()
	p := s.inner
	s.mu.RUnlock()
	if p == nil {
		return nil, fmt.Errorf("browser: no DOM engine is set (-dom, or PUT /api/scanner/dom): %w", errCapabilityMissing)
	}
	return p.Browser(ctx)
}

// Close releases the current engine's browser and keeps the engine set: the lazy provider starts
// a fresh one on the next request, as it does after any Close.
func (s *SwitchableBrowsers) Close() error {
	s.mu.RLock()
	p := s.inner
	s.mu.RUnlock()
	if p == nil {
		return nil
	}
	return p.Close()
}

// configuredProvider is a provider that can be present yet hold no engine (SwitchableBrowsers).
type configuredProvider interface{ Configured() bool }

// Configured forwards to a switchable provider; any other provider is an engine.
func (p scopedBrowsers) Configured() bool {
	if c, ok := p.BrowserProvider.(configuredProvider); ok {
		return c.Configured()
	}
	return true
}

// hasBrowsers reports whether this scanner has a DOM engine now: a provider is wired and, when it
// is a switch, the switch holds an engine. Every "no browser" branch asks this rather than
// comparing the field with nil, so an empty switch reads exactly like no engine.
func (s *ActiveScanner) hasBrowsers() bool {
	if s == nil || s.browsers == nil {
		return false
	}
	if c, ok := s.browsers.(configuredProvider); ok {
		return c.Configured()
	}
	return true
}

// EnableDOMChecks switches the DOM families on (ScanConfig.CheckDOM), the step WithBrowserProvider
// takes when an engine is wired at boot; the console takes it when it sets an engine at runtime.
// Removing the engine leaves the switch alone: the DOM checks then report a missing capability,
// which is the honest answer, and an operator's own choice of families is not overwritten.
func (s *ActiveScanner) EnableDOMChecks() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.config != nil {
		s.config.CheckDOM = true
	}
}
