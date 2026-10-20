package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// ceremony is the WebAuthn work the approval and registration pages need.
// passkeys implements it with go-webauthn; tests substitute a fake, because
// real assertions need a real authenticator.
type ceremony interface {
	beginLogin() (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	finishLogin(webauthn.SessionData, *http.Request) error
	beginRegistration() (*protocol.CredentialCreation, *webauthn.SessionData, error)
	finishRegistration(webauthn.SessionData, *http.Request) (*webauthn.Credential, error)
}

var errNoPasskeys = errors.New("no passkeys registered")

// owner is the single WebAuthn user: op-gate's approver. The handle is
// fixed, because a passkey's assertion carries it and must match on login.
type owner struct{ creds []webauthn.Credential }

func (owner) WebAuthnID() []byte                           { return []byte("op-gate-owner") }
func (owner) WebAuthnName() string                         { return "op-gate" }
func (owner) WebAuthnDisplayName() string                  { return "op-gate approver" }
func (o owner) WebAuthnCredentials() []webauthn.Credential { return o.creds }

type passkeys struct {
	wa    *webauthn.WebAuthn
	owner owner
}

// newPasskeys configures WebAuthn for the approval page at origin, such as
// https://op-gate.example.com. Passkeys are bound to its
// host. Browsers allow WebAuthn only on https origins and on
// http://localhost, which the browser tests use.
func newPasskeys(origin string, creds []webauthn.Credential) (*passkeys, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.Path != "" || !(u.Scheme == "https" || u.Scheme == "http" && u.Hostname() == "localhost") {
		return nil, fmt.Errorf("approval URL %q must be https://<host>", origin)
	}
	wa, err := webauthn.New(&webauthn.Config{RPID: u.Hostname(), RPDisplayName: "op-gate", RPOrigins: []string{origin}})
	if err != nil {
		return nil, err
	}
	return &passkeys{wa: wa, owner: owner{creds: creds}}, nil
}

func (p *passkeys) beginLogin() (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	if len(p.owner.creds) == 0 {
		return nil, nil, errNoPasskeys
	}
	// Required, not preferred: approving must take Face ID every time.
	return p.wa.BeginLogin(p.owner, webauthn.WithUserVerification(protocol.VerificationRequired))
}

func (p *passkeys) finishLogin(s webauthn.SessionData, r *http.Request) error {
	_, err := p.wa.FinishLogin(p.owner, s, r)
	return err
}

func (p *passkeys) beginRegistration() (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return p.wa.BeginRegistration(p.owner,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(webauthn.Credentials(p.owner.creds).CredentialDescriptors()),
	)
}

func (p *passkeys) finishRegistration(s webauthn.SessionData, r *http.Request) (*webauthn.Credential, error) {
	return p.wa.FinishRegistration(p.owner, s, r)
}

// loadPasskeys reads one credential per file in dir, typically a Kubernetes
// Secret with one key per passkey. Empty files are skipped. An invalid file
// is an error naming it, so a bad paste stops op-gate at startup instead of
// silently locking the approver out.
func loadPasskeys(dir string) ([]webauthn.Credential, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var creds []webauthn.Credential
	for _, e := range entries {
		// Secret volumes keep their real files under ..data and ..<timestamp>.
		if strings.HasPrefix(e.Name(), "..") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("passkey %q: %w", e.Name(), err)
		}
		if strings.TrimSpace(string(raw)) == "" {
			continue
		}
		var c webauthn.Credential
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("passkey %q: %w", e.Name(), err)
		}
		if len(c.ID) == 0 || len(c.PublicKey) == 0 {
			return nil, fmt.Errorf("passkey %q: missing id or publicKey", e.Name())
		}
		creds = append(creds, c)
	}
	return creds, nil
}
