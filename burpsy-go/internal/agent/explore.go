package agent

import (
	"fmt"
	"net/url"
	"strings"
)

// Finding is the part of an issue Explore Issue starts from.
type Finding struct {
	ID        string
	Name      string
	Severity  string
	URL       string
	MessageID string
	Evidence  string
}

// ExploreTask turns a finding into a run: the issue (and its message) attached, the scope narrowed
// to the finding's own host, and the evidence as untrusted context. It refuses a finding with no
// host to scope to rather than guess a wider one.
func ExploreTask(f Finding) (Task, error) {
	if strings.TrimSpace(f.ID) == "" {
		return Task{}, fmt.Errorf("explore: the finding has no id")
	}
	u, err := url.Parse(f.URL)
	if err != nil || u.Host == "" {
		return Task{}, fmt.Errorf("explore: finding %s has no usable host in %q, so there is nothing to scope the exploration to", f.ID, f.URL)
	}
	t := Task{
		ID:        "explore-" + f.ID,
		Goal:      fmt.Sprintf("Explore issue %q (%s severity) at %s: try to exploit it, look for further attack vectors on the same host, and summarise.", f.Name, f.Severity, f.URL),
		Scope:     []string{u.Host},
		Resources: []Resource{{Kind: ResourceIssue, Ref: f.ID, Title: f.Name}},
		Context:   f.Evidence,
	}
	if strings.TrimSpace(f.MessageID) != "" {
		t.Resources = append(t.Resources, Resource{Kind: ResourceProxy, Ref: f.MessageID})
	}
	return t, nil
}

const exploreBrief = `You are exploring one finding that a scanner reported. Confirm whether it is exploitable with minimal, targeted requests, look for related vectors on the same host, then finish with a summary and the further vectors you found. Prefer read and single-request tools; use attack-class tools only when a single request cannot answer the question.`

// NewExplorePlanner is the LLMPlanner with the Explore Issue brief.
func NewExplorePlanner(llm LLM, tools []ToolInfo) *LLMPlanner {
	return &LLMPlanner{LLM: llm, Tools: tools, System: exploreBrief}
}

// Attempt is one non-read step of an exploration.
type Attempt struct {
	Step       int        `json:"step"`
	Tool       string     `json:"tool"`
	Risk       Risk       `json:"risk"`
	Status     StepStatus `json:"status"`
	HTTPStatus int        `json:"http_status,omitempty"`
	Reason     string     `json:"reason,omitempty"`
}

// ExploreReport is what Explore Issue hands back: the summary, the vectors, and every attempt with
// whether a human let it run.
type ExploreReport struct {
	RunID    string    `json:"run_id"`
	Status   Status    `json:"status"`
	Summary  string    `json:"summary"`
	Vectors  []string  `json:"vectors"`
	Attempts []Attempt `json:"attempts"`
}

// BuildReport reads a finished run's snapshot.
func BuildReport(s Snapshot) ExploreReport {
	rep := ExploreReport{RunID: s.ID, Status: s.Status, Summary: s.Summary, Vectors: s.Vectors, Attempts: []Attempt{}}
	for _, st := range s.Steps {
		if st.Risk == RiskRead {
			continue
		}
		rep.Attempts = append(rep.Attempts, Attempt{Step: st.ID, Tool: st.Tool, Risk: st.Risk, Status: st.Status, HTTPStatus: st.HTTPStatus, Reason: st.Reason})
	}
	return rep
}
