package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// state is where an approval request stands. pending is the only state that
// changes; the others are final.
type state int

const (
	pending state = iota
	approved
	denied
	expired // the client gave up or the approval window closed
	failed  // the notification couldn't be sent
)

func (s state) String() string {
	return [...]string{"pending", "approved", "denied", "expired", "failed"}[s]
}

// settle returns the state a request in state from moves to when something
// tries to move it to to, and whether it moved. Only a pending request moves,
// so a request is decided exactly once: a tap can't revive an expired request,
// and a deadline can't undo an approval.
func settle(from, to state) (state, bool) {
	if from != pending {
		return from, false
	}
	return to, true
}

var errUnknownRequest = errors.New("unknown or expired request")

type approval struct {
	args    []string
	state   state
	session *webauthn.SessionData // the current passkey challenge; single use
	decided chan state            // receives the final state once
}

// approvals tracks requests waiting on the owner. It holds every request in
// memory, so op-gate runs as a single replica.
type approvals struct {
	baseURL string // where the approval page is served, e.g. https://op-gate.example.com
	notify  func(ctx context.Context, link string) error
	keep    time.Duration // how long a final request's page still shows its outcome

	mu   sync.Mutex
	reqs map[string]*approval
}

func newApprovals(baseURL string, notify func(context.Context, string) error) *approvals {
	return &approvals{baseURL: baseURL, notify: notify, keep: 10 * time.Minute, reqs: map[string]*approval{}}
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ask opens request id, sends the owner a link to its page, and waits for a
// decision or for ctx to end.
func (a *approvals) ask(ctx context.Context, id string, args []string) (bool, error) {
	r := &approval{args: args, state: pending, decided: make(chan state, 1)}
	a.mu.Lock()
	a.reqs[id] = r
	a.mu.Unlock()

	if err := a.notify(ctx, a.baseURL+"/approve/"+id); err != nil {
		a.decide(id, failed)
		return false, fmt.Errorf("sending notification: %w", err)
	}

	select {
	case st := <-r.decided:
		return st == approved, nil
	case <-ctx.Done():
		// A tap may have landed just before the deadline; the request's final
		// state decides, not which channel select happened to pick.
		if st, _ := a.decide(id, expired); st != expired {
			return st == approved, nil
		}
		return false, ctx.Err()
	}
}

// decide moves request id toward state to and returns the state it ends up in.
func (a *approvals) decide(id string, to state) (state, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.reqs[id]
	if !ok {
		return 0, errUnknownRequest
	}
	st, moved := settle(r.state, to)
	if moved {
		r.state = st
		r.session = nil
		r.decided <- st
		time.AfterFunc(a.keep, func() {
			a.mu.Lock()
			delete(a.reqs, id)
			a.mu.Unlock()
		})
	}
	return st, nil
}

// view returns request id's command and state for its page.
func (a *approvals) view(id string) ([]string, state, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.reqs[id]
	if !ok {
		return nil, 0, false
	}
	return r.args, r.state, true
}

// setSession stores a fresh passkey challenge for a pending request.
func (a *approvals) setSession(id string, s *webauthn.SessionData) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.reqs[id]
	switch {
	case !ok:
		return errUnknownRequest
	case r.state != pending:
		return fmt.Errorf("request is %s", r.state)
	}
	r.session = s
	return nil
}

// takeSession returns and clears request id's challenge, so each challenge
// can be answered once, right or wrong.
func (a *approvals) takeSession(id string) (*webauthn.SessionData, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.reqs[id]
	if !ok || r.state != pending || r.session == nil {
		return nil, false
	}
	s := r.session
	r.session = nil
	return s, true
}
