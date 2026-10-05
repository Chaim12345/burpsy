package web

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/burpsy-go/burpsy/internal/browser"
	"go.uber.org/zap"
)

// ---- Open browser (burpsy-react-ui-bufa) --------------------------------------------------------
//
// Burp's "Open browser": a Chromium on its own profile, routed through a live proxy listener and
// trusting burpsy's CA for that profile only — so a session starts by clicking a button rather than
// by configuring a browser's proxy and importing a CA into a machine-wide trust store. See
// internal/browser for the launch contract and why the CA is pinned rather than every certificate
// error ignored.

// browserLauncher returns the server's launcher, creating it on first use with the per-project
// default profile directory.
func (s *Server) browserLauncher() *browser.Launcher {
	s.browserOnce.Do(func() {
		s.browser = browser.New(s.defaultBrowserDir())
	})
	return s.browser
}

// defaultBrowserDir is the per-project profile directory: beside the project file, named for it, so
// two engagements' browsers never share cookies. A process with no -db gets one under the user cache.
func (s *Server) defaultBrowserDir() string {
	if s.persist != nil {
		db := s.persist.Path()
		base := strings.TrimSuffix(filepath.Base(db), filepath.Ext(db))
		return filepath.Join(filepath.Dir(db), "."+base+"-browser")
	}
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, "burpsy", "browser")
	}
	return filepath.Join(os.TempDir(), "burpsy-browser")
}

// restoreBrowserSettings loads the project's browser settings and re-points the default profile at
// the project — called from WithPersist, so a project switch also switches browser profile.
func (s *Server) restoreBrowserSettings() {
	l := s.browserLauncher()
	l.SetDefaultDir(s.defaultBrowserDir())
	set := browser.DefaultSettings()
	if s.persist != nil {
		if raw, err := s.persist.LoadBrowserSettings(); err != nil {
			s.logger.Warn("failed to restore browser settings; using defaults", zap.Error(err))
		} else if raw != nil {
			if err := json.Unmarshal(raw, &set); err != nil {
				s.logger.Warn("stored browser settings do not parse; using defaults", zap.Error(err))
				set = browser.DefaultSettings()
			}
		}
	}
	if err := l.SetSettings(set); err != nil {
		s.logger.Warn("stored browser settings refused; using defaults", zap.Error(err))
		_ = l.SetSettings(browser.DefaultSettings())
	}
}

// browserProxyAddr is the first listener a browser can use as an ordinary HTTP proxy: bound, not
// redirecting every request to one fixed host, not invisible (which expects non-proxy requests) and
// not forcing TLS. A wildcard bind is reached on loopback, which is where the browser runs.
func (s *Server) browserProxyAddr() string {
	if s.proxyServer == nil {
		return ""
	}
	for _, ls := range s.proxyServer.Listeners() {
		if ls.BoundAddr == "" || ls.RedirectHost != "" || ls.ForceTLS || (ls.Invisible != nil && *ls.Invisible) {
			continue
		}
		host, port, err := net.SplitHostPort(ls.BoundAddr)
		if err != nil {
			continue
		}
		if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
			host = "127.0.0.1"
		}
		return net.JoinHostPort(host, port)
	}
	return ""
}

// handleBrowserLaunch serves POST /api/browser/launch {url?}. riskEgress: the browser it opens loads
// the URL through the proxy, which is traffic to a target.
func (s *Server) handleBrowserLaunch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		URL string `json:"url"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, `the body must be empty or {"url": "..."}`, http.StatusBadRequest)
			return
		}
	}
	if u := strings.TrimSpace(req.URL); u != "" && !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		// Only web URLs: a file:// or chrome:// URL handed to a browser on the backend's machine is a
		// way to read that machine's files through the console.
		http.Error(w, "url must be an http:// or https:// URL", http.StatusBadRequest)
		return
	}
	spec := browser.Spec{ProxyAddr: s.browserProxyAddr(), URL: strings.TrimSpace(req.URL)}
	if s.tlsEngine != nil {
		if ca, _, ok := s.tlsEngine.ExportCA(); ok {
			spec.CA = ca
		}
	}
	// The DOM auditor extension (burpsy-react-ui-wl94): materialised fresh each launch so the current
	// canary and switch are baked in, and the web host bypassed so its hit reports are a direct
	// loopback POST rather than traffic through the proxy they describe. A materialisation failure is
	// logged and the browser still opens — the auditor is an addition, not a precondition for browsing.
	if dir, bypass, err := s.materialiseDomAuditor(); err != nil {
		s.logger.Warn("DOM auditor extension not loaded; the browser opens without it", zap.Error(err))
	} else if dir != "" {
		spec.Extensions = append(spec.Extensions, dir)
		if bypass != "" {
			spec.BypassProxyFor = append(spec.BypassProxyFor, bypass)
		}
	}
	res, err := s.browserLauncher().Launch(spec)
	if err != nil {
		// 503: every refusal is about this machine (no listener, no binary, root, no display), not
		// about the request — and it is worded for the operator, so it is returned as said.
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	s.logger.Info("operator browser launched", zap.String("proxy", res.Proxy),
		zap.String("profile", res.ProfileDir), zap.Bool("handed_off", res.HandedOff))
	writeJSON(w, http.StatusOK, res)
}

// browserSettingsView is the settings plus the facts the panel shows beside them.
type browserSettingsView struct {
	browser.Settings
	// ProfileDir is the directory a stored-data launch actually uses (the setting, or the per-project
	// default when the setting is empty).
	ProfileDir string `json:"profile_dir"`
	Running    bool   `json:"running"`
	// Proxy is the listener a launch would use, empty when none is usable — so the panel can say why
	// the button will refuse before it is pressed.
	Proxy string `json:"proxy"`
}

func (s *Server) browserSettingsView() browserSettingsView {
	l := s.browserLauncher()
	return browserSettingsView{Settings: l.Settings(), ProfileDir: l.ProfileDir(), Running: l.Running(), Proxy: s.browserProxyAddr()}
}

// handleBrowserSettings serves GET/PUT /api/browser/settings. riskLocal.
func (s *Server) handleBrowserSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.browserSettingsView())
	case http.MethodPut:
		// A whole document, merged onto the current one so a client sending one field changes one field.
		next := s.browserLauncher().Settings()
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&next); err != nil {
			http.Error(w, "the body must be a JSON object of browser settings", http.StatusBadRequest)
			return
		}
		if err := s.browserLauncher().SetSettings(next); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if s.persist != nil {
			if raw, err := json.Marshal(next); err == nil {
				if err := s.persist.SaveBrowserSettings(raw); err != nil {
					s.logger.Warn("browser settings persist failed", zap.Error(err))
				}
			}
		}
		writeJSON(w, http.StatusOK, s.browserSettingsView())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleBrowserClear serves POST /api/browser/clear — Burp's "Clear all browser data". riskDestructive:
// it deletes the profile's cookies, logins and history, which nothing can bring back.
func (s *Server) handleBrowserClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dir, err := s.browserLauncher().ClearData()
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"cleared": dir})
}
