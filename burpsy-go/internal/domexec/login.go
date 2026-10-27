package domexec

// Recorded-login replay (burpsy-react-ui-xhtk): Burp's "Replay" of a recorded login sequence, run in
// an isolated, scope-gated Session so the cookies it earns belong to that session alone.
//
// The step kinds are Burp's (Zf50): go to, click, type, TOTP, key press, wait. This package does not
// know about TOTP secrets — a TOTP step arrives as a type step whose Code function computes the text
// at the moment the step runs — and never puts a typed value into a result, an error or a
// description: the caller supplies the description, already redacted.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/egressgate"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/kb"
)

// LoginAction is one step to replay.
type LoginAction struct {
	// Kind is "goto", "click", "type", "totp" (a type step whose text is Code's), "key" or "wait".
	Kind     string
	URL      string
	Selector string
	XPath    string
	// Text is what a type step enters. Never echoed.
	Text string
	// Code, when set, computes a type step's text as the step runs (a TOTP code). It may block —
	// waiting out a time step whose code was already used — and must honour ctx.
	Code func(ctx context.Context) (string, error)
	Key  string
	Wait time.Duration
	// Description is the operator-facing line for this step, already free of secrets.
	Description string
}

// LoginCheck is the status check: load URL after the steps and look for Text in the page.
type LoginCheck struct {
	URL  string
	Text string
}

// LoginStepResult is how one step went.
type LoginStepResult struct {
	Index       int    `json:"index"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
	OK          bool   `json:"ok"`
	Error       string `json:"error,omitempty"`
	// URL is the page's address after the step, with query values and the fragment redacted
	// (RedactURL): an SSO hop carries code=, state= and #access_token= in exactly this field.
	URL       string `json:"url,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms"`
}

// LoginCheckResult is the status check's outcome.
type LoginCheckResult struct {
	URL   string `json:"url"`
	Found bool   `json:"found"`
	Error string `json:"error,omitempty"`
}

// LoginReplay is one replay's whole outcome.
type LoginReplay struct {
	// Succeeded is every step done, the final page in scope, and the status check (if any) found its
	// text. Anything less is a failed login, and Reason says which part.
	Succeeded bool `json:"succeeded"`
	// Verified is Succeeded AND a status check found its confirmation text. Without a status check a
	// login form that rejected the password still "runs every step" and ends on an in-scope page, so
	// Succeeded alone is "the steps ran", not "logged in" — the console words the two differently.
	Verified bool              `json:"verified"`
	Reason   string            `json:"reason,omitempty"`
	Steps    []LoginStepResult `json:"steps"`
	FinalURL string            `json:"final_url,omitempty"`
	Check    *LoginCheckResult `json:"status_check,omitempty"`
	// Blocked are the requests the scope gate refused during this replay.
	Blocked []string `json:"blocked"`
	// Screenshot is a JPEG of the page when the replay ended. Not marshalled; the caller decides
	// whether to publish it.
	Screenshot []byte            `json:"-"`
	Cookies    []*network.Cookie `json:"-"`
	ElapsedMS  int64             `json:"elapsed_ms"`
}

// ElementTimeout is how long a click or type step waits for its element to exist. A login page that
// renders its form from script needs a moment; one that never does should fail on this step, named.
const ElementTimeout = 10 * time.Second

// ReplayTimeout bounds one whole replay. Wait steps are capped at 10 s each and a TOTP step may wait
// out one period, so a long sequence is minutes, not hours.
const ReplayTimeout = 3 * time.Minute

// ReplayLogin runs actions in a new tab of this session, then the status check, and returns what
// happened. It does not return an error for a failed login — that is a result — only Reason.
func (s *Session) ReplayLogin(ctx context.Context, actions []LoginAction, check *LoginCheck) LoginReplay {
	started := time.Now()
	out := LoginReplay{Steps: []LoginStepResult{}, Blocked: []string{}}
	s.TakeBlocked()
	s.setReplaying(true)
	defer s.setReplaying(false)
	// A replay logs in from nothing. A re-login in a session that still holds the previous login's
	// cookies would be sent past the login form by many applications, and its first step would then
	// fail to find the field it types into.
	if err := s.clearCookies(ctx); err != nil {
		out.Reason = "the session's previous cookies could not be cleared: " + err.Error()
		out.ElapsedMS = time.Since(started).Milliseconds()
		return out
	}
	finish := func(reason string) LoginReplay {
		out.Reason = reason
		out.Succeeded = reason == ""
		out.Blocked = append(out.Blocked, s.TakeBlocked()...)
		out.ElapsedMS = time.Since(started).Milliseconds()
		return out
	}
	tabCtx, cancel, err := s.newTab(ctx, ReplayTimeout)
	if err != nil {
		return finish("the replay tab could not be opened: " + err.Error())
	}
	defer cancel()
	if err := chromedp.Run(tabCtx, chromedp.EmulateViewport(1280, 800)); err != nil {
		return finish("the replay tab could not be prepared: " + err.Error())
	}

	shoot := func() {
		_ = chromedp.Run(tabCtx, chromedp.ActionFunc(func(ctx context.Context) error {
			if buf := captureFrame(ctx); buf != nil {
				out.Screenshot = buf
			}
			return nil
		}))
	}

	for i, a := range actions {
		stepStarted := time.Now()
		res := LoginStepResult{Index: i + 1, Kind: a.Kind, Description: a.Description}
		err := runLoginAction(tabCtx, a)
		res.ElapsedMS = time.Since(stepStarted).Milliseconds()
		res.URL = RedactURL(currentURL(tabCtx))
		if err != nil {
			res.Error = err.Error()
			out.Steps = append(out.Steps, res)
			out.FinalURL = res.URL
			shoot()
			reason := fmt.Sprintf("step %d (%s) failed: %s", i+1, a.Description, err.Error())
			if strings.Contains(err.Error(), "ERR_CERT") {
				reason += "; the target's TLS certificate is not trusted — add its CA in Settings → Network, or turn " +
					"certificate verification off there (it applies to every leg, this replay included)"
			}
			if blocked := s.Blocked(); len(blocked) > 0 {
				reason += fmt.Sprintf("; the scope gate refused %d request(s) during the replay — an identity provider or asset host may need to be added to scope", len(blocked))
			}
			return finish(reason)
		}
		res.OK = true
		out.Steps = append(out.Steps, res)
	}
	settle(tabCtx, 5*time.Second)
	finalURL := currentURL(tabCtx)
	out.FinalURL = RedactURL(finalURL)
	shoot()

	// Burp: "the login sequence must end on a page that is in scope". An error page or an
	// out-of-scope landing is not a login.
	if fu, err := url.Parse(finalURL); err != nil || (fu.Scheme != "http" && fu.Scheme != "https") {
		return finish(fmt.Sprintf("the sequence did not end on a web page (%q)", out.FinalURL))
	} else if s.gate != nil {
		if err := s.gate.AllowURL(fu); err != nil {
			return finish("the sequence ended on a page outside the engagement scope: " + err.Error())
		}
	}

	if check != nil {
		cr := &LoginCheckResult{URL: check.URL}
		out.Check = cr
		var text string
		err := chromedp.Run(tabCtx,
			chromedp.Navigate(check.URL),
			chromedp.ActionFunc(func(ctx context.Context) error { settle(ctx, 5*time.Second); return nil }),
			chromedp.Evaluate(`document.body ? document.body.innerText : ""`, &text),
		)
		if err != nil {
			cr.Error = err.Error()
			shoot()
			return finish("the status check page could not be loaded: " + err.Error())
		}
		cr.Found = strings.Contains(text, check.Text)
		shoot()
		if !cr.Found {
			return finish("the status check page does not contain the confirmation text, so the login did not take")
		}
		out.Verified = true
	}

	cookies, err := s.Cookies(tabCtx)
	if err != nil {
		return finish("the session's cookies could not be read: " + err.Error())
	}
	out.Cookies = cookies
	return finish("")
}

func currentURL(ctx context.Context) string {
	var u string
	if err := chromedp.Run(ctx, chromedp.Location(&u)); err != nil {
		return ""
	}
	return u
}

// settle waits for the document to finish loading and the DOM to stop changing, bounded by max. Used
// between steps: a click that submits a form navigates, and the next step's element is on the next
// page.
func settle(ctx context.Context, max time.Duration) {
	waitForSettle(ctx, RenderOptions{DOMQuiet: 300 * time.Millisecond, NetworkIdle: DefaultNetworkIdle, MaxWait: max})
}

// locateJS finds the step's element by CSS selector, falling back to the recorded XPath, scrolls it
// into view and returns its centre in CSS pixels — or null when it is not there (yet).
const locateJS = `(function(sel, xp){
  var el = null;
  if (sel) { try { el = document.querySelector(sel); } catch (e) {} }
  if (!el && xp) { try { el = document.evaluate(xp, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue; } catch (e) {} }
  if (!el) return null;
  el.scrollIntoView({block: "center", inline: "center"});
  var r = el.getBoundingClientRect();
  return {x: r.left + r.width / 2, y: r.top + r.height / 2, w: r.width, h: r.height};
})`

type elementBox struct {
	X, Y, W, H float64
}

// locate polls for the element until ElementTimeout. Polling rather than waiting on a DOM event
// because the element may be on a page that has not arrived yet: the previous step's click is still
// navigating, and an evaluation during the navigation fails and is simply retried.
func locate(ctx context.Context, a LoginAction) (elementBox, error) {
	args, _ := json.Marshal([]string{a.Selector, a.XPath})
	expr := locateJS + ".apply(null, " + string(args) + ")"
	deadline := time.Now().Add(ElementTimeout)
	for {
		var box *elementBox
		err := chromedp.Evaluate(expr, &box).Do(ctx)
		if err == nil && box != nil && box.W > 0 && box.H > 0 {
			return *box, nil
		}
		if ctx.Err() != nil {
			return elementBox{}, ctx.Err()
		}
		if time.Now().After(deadline) {
			if err == nil && box != nil {
				return elementBox{}, errors.New("the element exists but is not visible")
			}
			return elementBox{}, fmt.Errorf("no element matched within %s", ElementTimeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func clickAt(ctx context.Context, box elementBox) error {
	for _, typ := range []input.MouseType{input.MousePressed, input.MouseReleased} {
		if err := input.DispatchMouseEvent(typ, box.X, box.Y).WithButton(input.Left).WithClickCount(1).Do(ctx); err != nil {
			return err
		}
	}
	return nil
}

// keyNames maps the editor's key names to chromedp's key strings.
var keyNames = map[string]string{
	"Enter": kb.Enter, "Tab": kb.Tab, "Escape": kb.Escape, "Backspace": kb.Backspace,
	"Delete": kb.Delete, "ArrowDown": kb.ArrowDown, "ArrowUp": kb.ArrowUp,
	"ArrowLeft": kb.ArrowLeft, "ArrowRight": kb.ArrowRight, "Home": kb.Home, "End": kb.End,
	"PageUp": kb.PageUp, "PageDown": kb.PageDown, "Space": " ",
}

func runLoginAction(tabCtx context.Context, a LoginAction) error {
	switch a.Kind {
	case "goto":
		if err := chromedp.Run(tabCtx, chromedp.Navigate(a.URL)); err != nil {
			return fmt.Errorf("navigation failed: %w", err)
		}
		settle(tabCtx, 5*time.Second)
		return nil
	case "click":
		return chromedp.Run(tabCtx, chromedp.ActionFunc(func(ctx context.Context) error {
			box, err := locate(ctx, a)
			if err != nil {
				return err
			}
			if err := clickAt(ctx, box); err != nil {
				return err
			}
			settle(ctx, 5*time.Second)
			return nil
		}))
	case "type", "totp":
		return chromedp.Run(tabCtx, chromedp.ActionFunc(func(ctx context.Context) error {
			box, err := locate(ctx, a)
			if err != nil {
				return err
			}
			// Focus by clicking, as the operator did when recording (Burp's best practice: "use
			// mouse clicks ... to interact with all elements"), then clear what is there so a
			// pre-filled field is not appended to.
			if err := clickAt(ctx, box); err != nil {
				return err
			}
			if err := chromedp.Evaluate(`(function(){var e=document.activeElement; if (e && "value" in e) { e.value=""; e.dispatchEvent(new Event("input",{bubbles:true})); }})()`, nil).Do(ctx); err != nil {
				return err
			}
			text := a.Text
			if a.Code != nil {
				code, err := a.Code(ctx)
				if err != nil {
					return fmt.Errorf("the code could not be generated: %w", err)
				}
				text = code
			}
			if err := chromedp.KeyEvent(text).Do(ctx); err != nil {
				return fmt.Errorf("typing failed: %w", err)
			}
			return nil
		}))
	case "key":
		k, ok := keyNames[a.Key]
		if !ok {
			if len([]rune(a.Key)) != 1 {
				return fmt.Errorf("key %q is not one this replay can press", a.Key)
			}
			k = a.Key
		}
		if err := chromedp.Run(tabCtx, chromedp.KeyEvent(k)); err != nil {
			return err
		}
		settle(tabCtx, 5*time.Second)
		return nil
	case "wait":
		select {
		case <-tabCtx.Done():
			return tabCtx.Err()
		case <-time.After(a.Wait):
			return nil
		}
	}
	return fmt.Errorf("unknown step kind %q", a.Kind)
}

// RedactURL keeps what an operator needs to recognise a page — scheme, host, path and the NAMES of its
// query parameters — and drops what an identity provider puts in a URL: query values and the fragment.
// A login's redirect chain carries code=, state=, SAMLResponse= and #access_token=, and a replay result
// or a crawl report that printed them would be the session it was careful not to print as a cookie.
func RedactURL(raw string) string { return egressgate.RedactURL(raw) }
