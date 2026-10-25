package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// fakeKeys stands in for the WebAuthn ceremony: a request body of "good"
// passes verification, anything else fails.
type fakeKeys struct{ none bool }

func (f fakeKeys) beginLogin() (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	if f.none {
		return nil, nil, errNoPasskeys
	}
	return &protocol.CredentialAssertion{}, &webauthn.SessionData{Challenge: "login"}, nil
}

func (fakeKeys) finishLogin(s webauthn.SessionData, r *http.Request) error {
	body, _ := io.ReadAll(r.Body)
	if s.Challenge != "login" || string(body) != "good" {
		return errors.New("bad assertion")
	}
	return nil
}

func (fakeKeys) beginRegistration() (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return &protocol.CredentialCreation{}, &webauthn.SessionData{Challenge: "register"}, nil
}

func (fakeKeys) finishRegistration(s webauthn.SessionData, r *http.Request) (*webauthn.Credential, error) {
	body, _ := io.ReadAll(r.Body)
	if s.Challenge != "register" || string(body) != "good" {
		return nil, errors.New("bad attestation")
	}
	return &webauthn.Credential{ID: []byte{1, 2, 3}, PublicKey: []byte{4, 5, 6}}, nil
}

// pendingRequest starts an ask for id and returns a channel with its result.
func pendingRequest(t *testing.T, w *web, id string) <-chan bool {
	t.Helper()
	got := make(chan bool, 1)
	notified := make(chan struct{})
	w.approvals.notify = func(context.Context, string) error { close(notified); return nil }
	go func() {
		v, _ := w.approvals.ask(context.Background(), id, testClient, []string{"read", "op://Agent/GitHub Token/credential"})
		got <- v == verdictApproved
	}()
	<-notified
	return got
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func newTestWeb(keys ceremony) *web {
	return newWeb(newApprovals("https://op-gate.example", nil), keys)
}

func TestApprovalPage(t *testing.T) {
	t.Run("shows the command while pending", func(t *testing.T) {
		w := newTestWeb(fakeKeys{})
		pendingRequest(t, w, "req1")
		rec := do(t, w.handler(), "GET", "/approve/req1", "")
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "op://Agent/GitHub Token/credential") || !strings.Contains(rec.Body.String(), "Approve") ||
			!strings.Contains(rec.Body.String(), "junction ("+testClient.short()+") wants to run") {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})

	t.Run("unknown request", func(t *testing.T) {
		w := newTestWeb(fakeKeys{})
		if rec := do(t, w.handler(), "GET", "/approve/nope", ""); rec.Code != http.StatusNotFound {
			t.Fatalf("code = %d", rec.Code)
		}
	})

	t.Run("passkey approves once", func(t *testing.T) {
		w := newTestWeb(fakeKeys{})
		result := pendingRequest(t, w, "req1")
		h := w.handler()
		if rec := do(t, h, "POST", "/approve/req1/options", ""); rec.Code != 200 {
			t.Fatalf("options: %d %s", rec.Code, rec.Body)
		}
		if rec := do(t, h, "POST", "/approve/req1/verify", "good"); rec.Code != 200 {
			t.Fatalf("verify: %d %s", rec.Code, rec.Body)
		}
		if !<-result {
			t.Fatal("request not approved")
		}
		page := do(t, h, "GET", "/approve/req1", "")
		if !strings.Contains(page.Body.String(), "<strong>approved</strong>") || strings.Contains(page.Body.String(), "<button") {
			t.Fatalf("final page still offers actions: %s", page.Body)
		}
		if rec := do(t, h, "POST", "/approve/req1/options", ""); rec.Code != http.StatusConflict {
			t.Fatalf("options after approval: %d", rec.Code)
		}
	})

	t.Run("passkey approves and caches", func(t *testing.T) {
		w := newTestWeb(fakeKeys{})
		result := pendingRequest(t, w, "req1")
		h := w.handler()
		do(t, h, "POST", "/approve/req1/options", "")
		if rec := do(t, h, "POST", "/approve/req1/verify?remember=1", "good"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "approved and cached") {
			t.Fatalf("verify: %d %s", rec.Code, rec.Body)
		}
		if !<-result {
			t.Fatal("request not approved")
		}
		if page := do(t, h, "GET", "/approve/req1", ""); !strings.Contains(page.Body.String(), "without asking for up to an hour") {
			t.Fatalf("page doesn't say the approval is cached: %s", page.Body)
		}
		if v, _ := w.approvals.ask(context.Background(), "req2", testClient, []string{"read", "op://Agent/GitHub Token/credential"}); v != verdictCacheHit {
			t.Fatalf("same command afterwards = %v, want a cache hit", v)
		}
	})

	t.Run("failed passkey check leaves the request pending, and the challenge is single use", func(t *testing.T) {
		w := newTestWeb(fakeKeys{})
		pendingRequest(t, w, "req1")
		h := w.handler()
		do(t, h, "POST", "/approve/req1/options", "")
		if rec := do(t, h, "POST", "/approve/req1/verify", "forged"); rec.Code != http.StatusForbidden {
			t.Fatalf("forged verify: %d", rec.Code)
		}
		if _, _, st, _ := w.approvals.view("req1"); st != pending {
			t.Fatalf("state = %v", st)
		}
		// The challenge was used up by the failed attempt; a replay needs new options.
		if rec := do(t, h, "POST", "/approve/req1/verify", "good"); rec.Code != http.StatusConflict {
			t.Fatalf("verify without fresh options: %d", rec.Code)
		}
	})

	t.Run("deny needs no passkey", func(t *testing.T) {
		w := newTestWeb(fakeKeys{})
		result := pendingRequest(t, w, "req1")
		if rec := do(t, w.handler(), "POST", "/approve/req1/deny", ""); rec.Code != 200 {
			t.Fatalf("deny: %d", rec.Code)
		}
		if <-result {
			t.Fatal("denied request approved")
		}
	})

	t.Run("no passkeys registered", func(t *testing.T) {
		w := newTestWeb(fakeKeys{none: true})
		pendingRequest(t, w, "req1")
		rec := do(t, w.handler(), "POST", "/approve/req1/options", "")
		if rec.Code != http.StatusPreconditionFailed || !strings.Contains(rec.Body.String(), "/register") {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
}

func TestRegistration(t *testing.T) {
	w := newTestWeb(fakeKeys{})
	h := w.handler()

	if rec := do(t, h, "GET", "/register", ""); rec.Code != 200 {
		t.Fatalf("page: %d", rec.Code)
	}
	rec := do(t, h, "POST", "/register/options", "")
	var opts struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &opts); err != nil || opts.Token == "" {
		t.Fatalf("options: %s", rec.Body)
	}

	rec = do(t, h, "POST", "/register/verify?token="+opts.Token, "good")
	var out struct {
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body)
	}
	// The line pasted into 1Password must load back as the same passkey.
	creds, err := loadPasskeys(writeFiles(t, map[string]string{"iphone": out.Credential}))
	if err != nil || len(creds) != 1 || string(creds[0].PublicKey) != "\x04\x05\x06" || strings.Contains(out.Credential, "\n") {
		t.Fatalf("credential line %q did not round-trip: %v", out.Credential, err)
	}

	if rec := do(t, h, "POST", "/register/verify?token="+opts.Token, "good"); rec.Code != http.StatusConflict {
		t.Fatalf("reused registration token: %d", rec.Code)
	}
}
