package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
)

// TestPasskeysEndToEnd runs registration and approval through the real
// handlers and go-webauthn, with a virtual authenticator standing in for the
// phone. It checks the round trip through the 1Password paste too.
func TestPasskeysEndToEnd(t *testing.T) {
	const origin = "https://op-gate.example.com"
	rp := virtualwebauthn.RelyingParty{Name: "op-gate", ID: "op-gate.example.com", Origin: origin}
	authOpts := virtualwebauthn.AuthenticatorOptions{UserHandle: owner{}.WebAuthnID()}
	phone := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// Register with no passkeys yet.
	keys, err := newPasskeys(origin, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newTestWeb(keys).handler()
	rec := do(t, h, "POST", "/register/options", "")
	var reg struct {
		Token   string          `json:"token"`
		Options json.RawMessage `json:"options"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reg); err != nil {
		t.Fatalf("register options: %s", rec.Body)
	}
	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(reg.Options))
	if err != nil {
		t.Fatal(err)
	}
	attestation := virtualwebauthn.CreateAttestationResponse(rp, virtualwebauthn.NewAuthenticatorWithOptions(authOpts), phone, *attOpts)
	rec = do(t, h, "POST", "/register/verify?token="+reg.Token, attestation)
	var out struct {
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Credential == "" {
		t.Fatalf("register verify: %d %s", rec.Code, rec.Body)
	}

	// "Paste" the line into the 1Password item and restart with it.
	creds, err := loadPasskeys(writeFiles(t, map[string]string{"iphone": out.Credential}))
	if err != nil {
		t.Fatal(err)
	}
	keys, err = newPasskeys(origin, creds)
	if err != nil {
		t.Fatal(err)
	}

	approveWith := func(t *testing.T, opts virtualwebauthn.AuthenticatorOptions) (int, bool) {
		w := newTestWeb(keys)
		result := pendingRequest(t, w, "req1")
		h := w.handler()
		rec := do(t, h, "POST", "/approve/req1/options", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("approve options: %d %s", rec.Code, rec.Body)
		}
		asOpts, err := virtualwebauthn.ParseAssertionOptions(rec.Body.String())
		if err != nil {
			t.Fatal(err)
		}
		assertion := virtualwebauthn.CreateAssertionResponse(rp, virtualwebauthn.NewAuthenticatorWithOptions(opts), phone, *asOpts)
		rec = do(t, h, "POST", "/approve/req1/verify", assertion)
		if rec.Code != http.StatusOK {
			return rec.Code, false
		}
		return rec.Code, <-result
	}

	t.Run("Face ID approves", func(t *testing.T) {
		if code, ok := approveWith(t, authOpts); code != http.StatusOK || !ok {
			t.Fatalf("code %d approved %v", code, ok)
		}
	})

	t.Run("a passkey without user verification is rejected", func(t *testing.T) {
		noFaceID := authOpts
		noFaceID.UserNotVerified = true
		if code, _ := approveWith(t, noFaceID); code != http.StatusForbidden {
			t.Fatalf("code = %d, want 403", code)
		}
	})

	t.Run("a different authenticator's passkey is rejected", func(t *testing.T) {
		stranger := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
		w := newTestWeb(keys)
		pendingRequest(t, w, "req1")
		h := w.handler()
		asOpts, _ := virtualwebauthn.ParseAssertionOptions(do(t, h, "POST", "/approve/req1/options", "").Body.String())
		assertion := virtualwebauthn.CreateAssertionResponse(rp, virtualwebauthn.NewAuthenticatorWithOptions(authOpts), stranger, *asOpts)
		if rec := do(t, h, "POST", "/approve/req1/verify", assertion); rec.Code != http.StatusForbidden {
			t.Fatalf("code = %d", rec.Code)
		}
	})

	if strings.Contains(out.Credential, "privateKey") {
		t.Fatal("the pasted line must hold only public data")
	}
}
