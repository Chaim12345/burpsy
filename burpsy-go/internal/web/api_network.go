package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// ---- Network settings --------------------------------------------------------------------------
//
// Burp's Settings → Network, as one endpoint: hostname resolution, the DNS lookup policy, the three
// timeouts, the redirect policy, 100-continue handling and open-ended responses.
//
// GET answers the whole live state. PUT is a partial patch over the nested document — a section the
// body omits is untouched, a key a section omits is untouched — and an unknown key at either level is
// refused by name. That refusal is the point rather than politeness: every key here decides where
// bytes go or how long we wait for them, so a typo silently ignored would leave the operator reading
// a panel that agrees with them and a sender that does not.
//
// The patch is validated in full and applied as one unit. sender.ApplyNetwork changes nothing on a
// refusal, so a body with one bad value leaves the previous settings entirely in force; there is no
// state in which half the document is live.

// networkSettingsView is one answer: the live settings, plus what the endpoint will accept.
//
// `accepted` travels with the state for the same reason /api/proxy/options ships its key list — a
// panel that hardcoded the enum arms would drift from the server the first time one was added, and
// the refusal messages name these values, so the client can show them without guessing.
type networkSettingsView struct {
	Settings sender.NetworkSettings `json:"settings"`
	Accepted networkAcceptedView    `json:"accepted"`
}

type networkAcceptedView struct {
	ResolutionPolicies []string `json:"resolution_policies"`
	// ResolutionFamilies is read from the engine, not hardcoded in the panel, so a family value can
	// appear in the selector only if the engine accepts it — the same rule the policy list follows.
	ResolutionFamilies []string `json:"resolution_families"`
	RedirectModes      []string `json:"redirect_modes"`
	MaxTimeoutMS       int      `json:"max_timeout_ms"`
	MaxRedirectHops    int      `json:"max_redirect_hops"`
	MaxHostOverrides   int      `json:"max_host_overrides"`
	MaxStreamingHosts  int      `json:"max_streaming_hosts"`
	// Keys is every patchable dotted key, sorted. The unknown-key refusal points at this list, so it
	// has to be derived from the same table that decides the refusal rather than typed out beside it.
	Keys []string `json:"keys"`
}

func networkAccepted() networkAcceptedView {
	keys := make([]string, 0, 16)
	for section, fields := range networkPatchFields {
		for key := range fields {
			keys = append(keys, section+"."+key)
		}
	}
	sort.Strings(keys)
	return networkAcceptedView{
		ResolutionPolicies: []string{string(sender.ResolutionSystem), string(sender.ResolutionResolver)},
		// Read from the engine so the panel's selector can only offer a value Validate accepts, the
		// same rule ResolutionPolicies and RedirectModes follow.
		ResolutionFamilies: []string{
			string(sender.FamilySystem), string(sender.FamilyIPv4), string(sender.FamilyIPv6),
		},
		RedirectModes: []string{
			string(sender.RedirectNever), string(sender.RedirectOnSite),
			string(sender.RedirectInScope), string(sender.RedirectAlways),
		},
		MaxTimeoutMS:      sender.MaxTimeoutMS,
		MaxRedirectHops:   sender.MaxRedirectHops,
		MaxHostOverrides:  sender.MaxHostOverrides,
		MaxStreamingHosts: sender.MaxStreamingHosts,
		Keys:              keys,
	}
}

// networkPatchFields is the whole writable surface, keyed section then field, exactly as the wire
// spells them. A setting that is not in this table cannot be written, and its dotted name here is the
// name a refusal uses — which is what keeps the error message and the accepted-key list from being two
// independent claims about the same thing.
//
// Each applier decodes into the field it owns and returns a message naming what the key wants. The
// value bounds are NOT checked here: sender.NetworkSettings.Validate owns them, and duplicating a
// bound is how the two copies come to disagree. Only the shape — number, string, list — is decided at
// this layer, because a JSON string where a number belongs cannot reach Validate at all.
var networkPatchFields = map[string]map[string]func(*sender.NetworkSettings, json.RawMessage) error{
	"resolution": {
		"overrides": func(n *sender.NetworkSettings, raw json.RawMessage) error {
			var out []sender.HostOverride
			if err := strictUnmarshal(raw, &out); err != nil {
				return fmt.Errorf("wants a list of {host, address, enabled} objects: %v", err)
			}
			n.Resolution.Overrides = out
			return nil
		},
		"policy": func(n *sender.NetworkSettings, raw json.RawMessage) error {
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return fmt.Errorf("wants a policy name as a string")
			}
			n.Resolution.Policy = sender.ResolutionPolicy(s)
			return nil
		},
		// Burp's resolution-address preference (settings/network/dns.html:49-65), which exists
		// "because routing restrictions may permit only one family" (burpsy-react-ui-mr83 part 2).
		// The refusal names the three values so a typo is a message rather than a silent filter that
		// matches no address.
		"family": func(n *sender.NetworkSettings, raw json.RawMessage) error {
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return fmt.Errorf("wants a family name as a string")
			}
			n.Resolution.Family = sender.AddressFamily(s)
			return nil
		},
		"resolver": func(n *sender.NetworkSettings, raw json.RawMessage) error {
			return patchString(raw, &n.Resolution.Resolver)
		},
		"timeout_ms": func(n *sender.NetworkSettings, raw json.RawMessage) error {
			return patchInt(raw, &n.Resolution.TimeoutMS)
		},
	},
	"timeouts": {
		"connect_ms": func(n *sender.NetworkSettings, raw json.RawMessage) error {
			return patchInt(raw, &n.Timeouts.ConnectMS)
		},
		"read_ms":  func(n *sender.NetworkSettings, raw json.RawMessage) error { return patchInt(raw, &n.Timeouts.ReadMS) },
		"total_ms": func(n *sender.NetworkSettings, raw json.RawMessage) error { return patchInt(raw, &n.Timeouts.TotalMS) },
	},
	"redirects": {
		"mode": func(n *sender.NetworkSettings, raw json.RawMessage) error {
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return fmt.Errorf("wants a mode name as a string")
			}
			n.Redirects.Mode = sender.RedirectMode(s)
			return nil
		},
		"max_hops": func(n *sender.NetworkSettings, raw json.RawMessage) error { return patchInt(raw, &n.Redirects.MaxHops) },
		// Burp's "Follow redirections and resubmit cookies" (settings/tools/repeater.html:143-145),
		// which burpsy lacked entirely (burpsy-react-ui-mr83). Off by default here as it is there: a
		// cookie the target set mid-chain is not something the operator asked to send.
		"replay_cookies": func(n *sender.NetworkSettings, raw json.RawMessage) error {
			return patchBool(raw, &n.Redirects.ReplayCookies)
		},
	},
	"continue": {
		"understand_100_continue": func(n *sender.NetworkSettings, raw json.RawMessage) error {
			return patchBool(raw, &n.Continue.Understand100)
		},
		"remove_expect_header": func(n *sender.NetworkSettings, raw json.RawMessage) error {
			return patchBool(raw, &n.Continue.RemoveExpect)
		},
		"expect_continue_timeout_ms": func(n *sender.NetworkSettings, raw json.RawMessage) error {
			return patchInt(raw, &n.Continue.ExpectTimeoutMS)
		},
	},
	"tls": {
		"verify": func(n *sender.NetworkSettings, raw json.RawMessage) error {
			return patchBool(raw, &n.TLS.Verify)
		},
		"root_ca_path": func(n *sender.NetworkSettings, raw json.RawMessage) error {
			return patchString(raw, &n.TLS.RootCAPath)
		},
		"min_version": func(n *sender.NetworkSettings, raw json.RawMessage) error {
			var v uint16
			if err := json.Unmarshal(raw, &v); err != nil {
				return fmt.Errorf("wants the TLS version number: 0x0301 for TLS 1.0, 0x0302 for 1.1, " +
					"0x0303 for 1.2, 0x0304 for 1.3")
			}
			n.TLS.MinVersion = v
			return nil
		},
	},
	"streaming": {
		"hosts": func(n *sender.NetworkSettings, raw json.RawMessage) error {
			var out []string
			if err := json.Unmarshal(raw, &out); err != nil {
				return fmt.Errorf("wants a list of host patterns")
			}
			n.Streaming.Hosts = out
			return nil
		},
		"timeout_ms": func(n *sender.NetworkSettings, raw json.RawMessage) error {
			return patchInt(raw, &n.Streaming.TimeoutMS)
		},
		"store": func(n *sender.NetworkSettings, raw json.RawMessage) error {
			// A pointer field, so a document that never set it reads as the shipped on rather than a
			// bare false — see StreamingSettings.Store. The patch always carries an explicit value, so
			// here the pointer is always set.
			var b bool
			if err := json.Unmarshal(raw, &b); err != nil {
				return fmt.Errorf("wants true or false")
			}
			n.Streaming.Store = &b
			return nil
		},
		"strip_chunked_encoding_metadata": func(n *sender.NetworkSettings, raw json.RawMessage) error {
			return patchBool(raw, &n.Streaming.StripChunkedMetadata)
		},
		"use_text_event_stream_header": func(n *sender.NetworkSettings, raw json.RawMessage) error {
			return patchBool(raw, &n.Streaming.UseTextEventStreamHeader)
		},
	},
}

func patchInt(raw json.RawMessage, into *int) error {
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		return fmt.Errorf("wants a whole number of milliseconds")
	}
	*into = n
	return nil
}

func patchBool(raw json.RawMessage, into *bool) error {
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return fmt.Errorf("wants true or false")
	}
	*into = b
	return nil
}

func patchString(raw json.RawMessage, into *string) error {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("wants a string")
	}
	*into = s
	return nil
}

// strictUnmarshal decodes with unknown object fields refused.
//
// Used for the override list because a misspelled member — `addr` for `address` — would otherwise
// decode to an entry with an empty address. Validate would then refuse it, which is not wrong, but the
// message would say the address is missing when what is actually wrong is the key that was typed. The
// stricter decode names the real mistake.
func strictUnmarshal(raw json.RawMessage, into any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(into)
}

// handleNetworkSettings serves GET/PUT /api/network/settings.
func (s *Server) handleNetworkSettings(w http.ResponseWriter, r *http.Request) {
	// Verb dispatch first, matching handleScannerConfig and handleProxyOptions: a wrong verb is 405
	// whatever the process is carrying, and the manifest test holds the route to that.
	switch r.Method {
	case http.MethodGet:
		if s.sender == nil {
			http.Error(w, "No sender is attached to this server, so there are no network settings to manage", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, networkSettingsView{Settings: s.sender.Network(), Accepted: networkAccepted()})
	case http.MethodPut:
		if s.sender == nil {
			http.Error(w, "No sender is attached to this server, so there are no network settings to manage", http.StatusServiceUnavailable)
			return
		}
		s.applyNetworkSettingsPatch(w, r)
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) applyNetworkSettingsPatch(w http.ResponseWriter, r *http.Request) {
	var patch map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		http.Error(w, "Body must be a JSON object of network setting sections", http.StatusBadRequest)
		return
	}
	if len(patch) == 0 {
		http.Error(w, "Body must set at least one network setting", http.StatusBadRequest)
		return
	}

	// The patch is built on top of the live settings, so an omitted key keeps the value it has rather
	// than reverting to a default. A patch merged against DefaultNetworkSettings instead would turn
	// every single-key edit into a silent reset of everything else.
	next := s.sender.Network()
	for section, body := range patch {
		fields, known := networkPatchFields[section]
		if !known {
			http.Error(w, fmt.Sprintf("unknown network settings section %q; the sections are listed under "+
				"\"accepted\" in the GET answer", section), http.StatusBadRequest)
			return
		}
		var members map[string]json.RawMessage
		if err := json.Unmarshal(body, &members); err != nil {
			http.Error(w, fmt.Sprintf("section %q must be a JSON object of settings", section),
				http.StatusBadRequest)
			return
		}
		for key, raw := range members {
			apply, ok := fields[key]
			if !ok {
				http.Error(w, fmt.Sprintf("unknown network setting %q; the keys are listed under "+
					"\"accepted\" in the GET answer", section+"."+key), http.StatusBadRequest)
				return
			}
			if err := apply(&next, raw); err != nil {
				http.Error(w, fmt.Sprintf("key %q %v", section+"."+key, err), http.StatusBadRequest)
				return
			}
		}
	}

	// One apply for the whole document. ApplyNetwork normalises, validates and refuses as a unit, so
	// the failure below means nothing changed — which is why the operator can retry a corrected body
	// against a sender still in the state the panel last showed.
	if err := s.sender.ApplyNetwork(next); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// The proxy leg reads the same streaming settings, and this is the one place they change.
	//
	// Without this the panel would describe a host list that only the sender obeyed, while browser
	// traffic through the proxy kept buffering — the exact "a rule that silently lapses for part of
	// the traffic" failure this file's other comments keep warning about, in the one surface where an
	// operator is most likely to be reading the setting: an event stream that arrives empty
	// (burpsy-react-ui-wet3).
	//
	// A refusal here is reported rather than swallowed, and it is not: Set only refuses a negative
	// window, which Normalise has already rejected above, so this cannot fail on a document the sender
	// accepted. The check is here so that if it ever can, the operator is told instead of the proxy
	// silently keeping the previous list.
	// The upstream-TLS policy, pushed to the proxy leg for the same reason the streaming settings are:
	// one console edit, both legs. A refusal here is reported rather than swallowed — unlike the
	// sender's CA load, a bundle that will not parse is the operator's mistake and saying so at the
	// moment they save it is the difference between a fixable error and a handshake failure twenty
	// minutes later (burpsy-react-ui-f365).
	if s.proxyServer != nil {
		tlsPolicy := s.proxyServer.TLS()
		tlsPolicy.WithVerify(next.TLS.Verify)
		if minErr := tlsPolicy.WithMinVersion(next.TLS.MinVersion); minErr != nil {
			http.Error(w, minErr.Error(), http.StatusBadRequest)
			return
		}
		if caPath := next.TLS.RootCAPath; caPath != "" {
			if caErr := tlsPolicy.WithRootCAFile(caPath); caErr != nil {
				http.Error(w, "tls.root_ca_path: "+caErr.Error(), http.StatusBadRequest)
				return
			}
		}
	}

	if s.proxyServer != nil {
		if err := s.proxyServer.Streaming().Set(next.Streaming.Hosts, time.Duration(next.Streaming.TimeoutMS)*time.Millisecond); err != nil {
			s.logger.Warn("proxy streaming policy refused settings the sender accepted", zap.Error(err))
		}
		// The three response-handling switches reach the proxy leg for the same reason the host list
		// does: one console edit, both legs. StoreStreamed reads a nil (never-set, or loaded from a
		// document that predates the switch) as on, so an operator who never opened the panel keeps the
		// recording behaviour that shipped.
		s.proxyServer.Streaming().SetResponseHandling(
			next.Streaming.StoreStreamed(),
			next.Streaming.StripChunkedMetadata,
			next.Streaming.UseTextEventStreamHeader,
		)
		// The resolution and 100-continue half, pushed for exactly the same reason: without it a
		// hostname override would apply to Repeater and silently not to the browser traffic the
		// operator is driving through the proxy, and an interim 100 would be handed to the client
		// as its response (burpsy-react-ui-o1eu). Set cannot fail — the document was validated
		// above — so there is no refusal to report here.
		s.proxyServer.Network().Set(next.Resolution, next.Continue)
	}

	confirmed := s.sender.Network()
	if s.persist != nil {
		if err := s.persist.SaveNetworkSettings(confirmed); err != nil {
			// The live sender already has the edit, so this answers 200: the operator's immediate
			// intent took effect and only its durability is in doubt. Reported rather than swallowed,
			// matching /api/scanner/config.
			s.logger.Warn("network settings persist failed", zap.Error(err))
		}
	}
	writeJSON(w, http.StatusOK, networkSettingsView{Settings: confirmed, Accepted: networkAccepted()})
}
