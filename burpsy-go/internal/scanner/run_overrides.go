package scanner

// Per-run project-option overrides (burpsy-react-ui-o2p3): Burp's
// scanner/audit_optimization/follow_redirections and
// scanner/audit_project_option_overrides/{connect_timeout,normal_timeout}, applied to the run that
// carries them and to nothing else.
//
// # Burp's semantics, as adopted (build 51467, /root/burp-re/out/clean/jdt_src/burp/)
//
//   - follow_redirections is a BOOLEAN scan-configuration key (Zhd_.java:41 reads it with the boolean
//     getter, :55 writes it with the boolean setter). It is not the four-way project redirect mode
//     (Zxt4.java: NEVER_FOLLOW, FOLLOW_ON_SITE, FOLLOW_IN_SCOPE, ALWAYS_FOLLOW), which governs Repeater
//     and the project and has no scan-configuration key. The documentation names the rule the
//     boolean switches on ("Follow redirections where necessary", scanner/scan-configurations/
//     audit-settings.html): a request in the target scope follows only redirects within that scope; a
//     request outside it follows only redirects to the same host and port. burpsy maps that onto
//     sender.RedirectInScope when an engagement scope is configured and sender.RedirectOnSite when none
//     is — with no scope, nothing is "in scope" in Burp's sense, so its out-of-scope rule applies.
//   - connect_timeout and normal_timeout are whole SECONDS (Zbuj.java:19-22 builds Duration.ofSeconds
//     from them), -1 means "not overridden" (Zbuj.java:27-28 writes -1 for an absent override and :20,22
//     read `> -1` as set), and zero is "never time out" (desktop/settings/network/connections.html:
//     "If you set any of these settings to zero or leave them blank, Burp will never time out").
//
// # "Where necessary"
//
// Burp's documentation gives the reason for the setting — "cross-site scripting in an error message
// that is only returned after following a redirect" — and its per-check predicate for "necessary"
// was not located in the decompiled tree. burpsy follows for the one check the documentation names,
// reflected XSS, and for no other: following inside every probe would hand the open-redirection check
// a 200 instead of the 30x whose Location it reads, and the header-injection check the landing page
// instead of the response that carried the injected header. Every other check reads the 30x itself,
// with or without the key, and the key row says so.

import (
	"context"
	"fmt"
	"time"

	"github.com/burpsy-go/burpsy/internal/sender"
)

// runSenderKey carries a run's derived sender on the dispatch context. Read only by probeGate.
type runSenderKey struct{}

func withRunSender(ctx context.Context, snd *sender.Sender) context.Context {
	if snd == nil {
		return ctx
	}
	return context.WithValue(ctx, runSenderKey{}, snd)
}

// runSenderFrom returns the run's derived sender, or nil when the run has none.
func runSenderFrom(ctx context.Context) *sender.Sender {
	if ctx == nil {
		return nil
	}
	snd, _ := ctx.Value(runSenderKey{}).(*sender.Sender)
	return snd
}

// timeoutOverride is the run's two Burp timeouts as the sender's override shape. An unset key is a nil
// field, so the engagement's own bound stands for it.
func (cfg AuditConfig) timeoutOverride() sender.TimeoutOverride {
	var o sender.TimeoutOverride
	if cfg.ConnectTimeout.Set {
		d := time.Duration(cfg.ConnectTimeout.Value) * time.Second
		o.Connect = &d
	}
	if cfg.NormalTimeout.Set {
		d := time.Duration(cfg.NormalTimeout.Value) * time.Second
		o.Normal = &d
	}
	return o
}

// runSenderFor derives the sender one run's probes leave through, or returns nil when the run
// overrides nothing — in which case every probe uses the engagement sender exactly as before.
//
// An error means the override cannot be applied, and the caller must refuse the run's items rather
// than run them under the engagement's timeouts: a configuration that said "30 s" quietly running
// under 10 s is the silent substitution this whole feature exists to remove.
func (s *ActiveScanner) runSenderFor(cfg AuditConfig) (*sender.Sender, error) {
	o := cfg.timeoutOverride()
	if o.Empty() || s == nil || s.sender == nil {
		return nil, nil
	}
	snd, err := s.sender.DeriveWithTimeouts(o)
	if err != nil {
		return nil, fmt.Errorf("audit_project_option_overrides: %w", err)
	}
	return snd, nil
}

// redirectPolicy is the redirect policy a probe that follows "where necessary" uses under this run,
// and whether the run follows at all. The hop budget and the cookie-replay choice are the
// engagement's network settings, because Burp's scan configuration names neither.
func (s *ActiveScanner) redirectPolicy(ctx context.Context) (sender.RedirectSettings, bool) {
	cfg, ok := runConfigFrom(ctx)
	if !ok || !cfg.FollowRedirects.Set || cfg.FollowRedirects.Value == 0 || s == nil || s.sender == nil {
		return sender.RedirectSettings{Mode: sender.RedirectNever}, false
	}
	engagement := s.sender.Network().Redirects
	policy := sender.RedirectSettings{
		Mode:          sender.RedirectInScope,
		MaxHops:       engagement.MaxHops,
		ReplayCookies: engagement.ReplayCookies,
	}
	if s.scope == nil {
		policy.Mode = sender.RedirectOnSite
	}
	if policy.MaxHops <= 0 {
		policy.MaxHops = sender.DefaultNetworkSettings().Redirects.MaxHops
	}
	return policy, true
}
