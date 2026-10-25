package dominvader

import (
	"fmt"
	"net/url"
	"regexp"
)

// PollutionConfig is an explicit, default-off probe plan. Properties name the
// finite gadget vocabulary being tried, not a claim to discover every gadget.
// Target is the one document under test; the server scope-checks it before use.
type PollutionConfig struct {
	Enabled    bool     `json:"enabled"`
	Target     string   `json:"target"`
	Query      bool     `json:"query"`
	Hash       bool     `json:"hash"`
	JSON       bool     `json:"json"`
	Nested     bool     `json:"nested"`
	Properties []string `json:"properties"`
}

var pollutionProperty = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]{0,63}$`)

// Validate refuses incomplete or dangerous plans before any setting changes.
func (p PollutionConfig) Validate() error {
	if !p.Enabled {
		return nil
	}
	if !p.Query && !p.Hash && !p.JSON {
		return fmt.Errorf("choose at least one pollution technique")
	}
	if len(p.Properties) == 0 || len(p.Properties) > 16 {
		return fmt.Errorf("choose 1 to 16 gadget properties")
	}
	for _, prop := range p.Properties {
		if !pollutionProperty.MatchString(prop) || prop == "__proto__" || prop == "constructor" || prop == "prototype" {
			return fmt.Errorf("invalid gadget property %q", prop)
		}
	}
	u, err := url.Parse(p.Target)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return fmt.Errorf("pollution target must be an absolute HTTP(S) URL without credentials")
	}
	return nil
}

// SetPollution replaces the plan only after complete validation. The API must
// also check current scope; this store has no authority to open target sockets.
func (s *Store) SetPollution(p PollutionConfig) error {
	if err := p.Validate(); err != nil {
		return err
	}
	p.Properties = append([]string(nil), p.Properties...)
	s.mu.Lock()
	s.pollution = p
	s.mu.Unlock()
	s.signal()
	return nil
}

func (s *Store) Pollution() PollutionConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := s.pollution
	p.Properties = append([]string(nil), p.Properties...)
	return p
}
