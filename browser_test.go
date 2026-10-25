package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	cdpwebauthn "github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
)

// TestPageScripts drives the registration and approval pages in headless
// Chromium with a virtual authenticator, so the pages' scripts (the
// ArrayBuffer <-> base64url conversions) run against the real server. It's
// skipped where no Chromium is installed.
func TestPageScripts(t *testing.T) {
	var browser string
	for _, name := range []string{"chromium-browser", "chromium", "google-chrome", "google-chrome-stable"} {
		if p, err := exec.LookPath(name); err == nil {
			browser = p
			break
		}
	}
	if browser == "" {
		t.Skip("no Chromium installed")
	}

	// The handler is swapped between registering and approving, the way a
	// restart picks up a new passkey in production.
	var mu sync.Mutex
	var current http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		h := current
		mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	origin := "http://localhost:" + u.Port() // WebAuthn allows http only on localhost
	use := func(w *web) { mu.Lock(); current = w.handler(); mu.Unlock() }

	keys, err := newPasskeys(origin, nil)
	if err != nil {
		t.Fatal(err)
	}
	use(newTestWeb(keys))

	// No sandbox: Ubuntu 24.04 (GitHub's runners) blocks the user namespaces
	// Chromium's sandbox needs, and the test only loads its own local pages.
	alloc, cancel := chromedp.NewExecAllocator(context.Background(),
		append(chromedp.DefaultExecAllocatorOptions[:], chromedp.ExecPath(browser), chromedp.NoSandbox)...)
	defer cancel()
	ctx, cancel := chromedp.NewContext(alloc)
	defer cancel()
	// The deadline covers starting Chromium, which can take over 30s cold on a CI runner.
	ctx, cancel = context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	// A phone-like authenticator: resident keys and Face ID that succeeds.
	if err := chromedp.Do(ctx, chromedp.Navigate(origin+"/register")); err != nil {
		t.Fatal(err)
	}
	if _, err := chromedp.Call(ctx, cdpwebauthn.Enable, cdpwebauthn.EnableParams{}); err != nil {
		t.Fatal(err)
	}
	if _, err := chromedp.Call(ctx, cdpwebauthn.AddVirtualAuthenticator, cdpwebauthn.AddVirtualAuthenticatorParams{
		Options: &cdpwebauthn.VirtualAuthenticatorOptions{
			Protocol: cdpwebauthn.AuthenticatorProtocolCtap2, Transport: cdpwebauthn.AuthenticatorTransportInternal,
			HasResidentKey: true, HasUserVerification: true, IsUserVerified: true, AutomaticPresenceSimulation: true,
		},
	}); err != nil {
		t.Fatal(err)
	}

	if err := chromedp.Do(ctx, chromedp.Click(chromedp.CSS("button")), chromedp.WaitVisible(chromedp.ID("out"))); err != nil {
		t.Fatalf("registering in the browser: %v", err)
	}
	line, err := chromedp.Run(ctx, chromedp.Value(chromedp.ID("out")))
	if err != nil {
		t.Fatal(err)
	}

	creds, err := loadPasskeys(writeFiles(t, map[string]string{"chromium": line}))
	if err != nil {
		t.Fatalf("registered line %q: %v", line, err)
	}
	keys, err = newPasskeys(origin, creds)
	if err != nil {
		t.Fatal(err)
	}
	w := newTestWeb(keys)
	use(w)
	result := pendingRequest(t, w, "req1")

	err = chromedp.Do(ctx,
		chromedp.Navigate(origin+"/approve/req1"),
		chromedp.Click(chromedp.CSS("button")), // Approve with Face ID
	)
	if err != nil {
		t.Fatalf("approving in the browser: %v", err)
	}
	if _, err := chromedp.Run(ctx, chromedp.Poll[bool](`document.body.textContent.includes('approved')`)); err != nil {
		msg, _ := chromedp.Run(ctx, chromedp.Text(chromedp.CSS("body")))
		t.Fatalf("page never showed the approval: %v; page says %q", err, strings.TrimSpace(msg))
	}
	select {
	case ok := <-result:
		if !ok {
			t.Fatal("request not approved")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("approval never reached the request")
	}

	result = pendingRequest(t, w, "req2")
	err = chromedp.Do(ctx,
		chromedp.Navigate(origin+"/approve/req2"),
		chromedp.Click(chromedp.CSS("button.cache")),
	)
	if err != nil {
		t.Fatalf("approving and caching in the browser: %v", err)
	}
	if _, err := chromedp.Run(ctx, chromedp.Poll[bool](`document.body.textContent.includes('approved and cached')`)); err != nil {
		msg, _ := chromedp.Run(ctx, chromedp.Text(chromedp.CSS("body")))
		t.Fatalf("page never showed the cached approval: %v; page says %q", err, strings.TrimSpace(msg))
	}
	if ok := <-result; !ok {
		t.Fatal("cached request not approved")
	}
	if v, _ := w.approvals.ask(ctx, "req3", testClient, []string{"read", "op://Agent/GitHub Token/credential"}); v != verdictCacheHit {
		t.Fatalf("same command afterwards = %v, want a cache hit", v)
	}
}
