package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// state is where an approval request stands. pending is the only state that
// changes; the others are final.
type state int

const (
	pending state = iota
	approved
	approvedAndCached // approved, and the same command runs again without asking for a while
	denied
	expired // the client gave up or the approval window closed
	failed  // the notification couldn't be sent
)

func (s state) String() string {
	return [...]string{"pending", "approved", "approved and cached", "denied", "expired", "failed"}[s]
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

// verdict is what ask decided. verdictDenied is the zero value, so an error
// path that returns verdict(0) can never be read as an approval.
type verdict int

const (
	verdictDenied verdict = iota
	verdictApproved
	verdictCacheHit // a cached approval allowed it; nobody was asked
)

// String is the request's outcome in logs and spans.
func (v verdict) String() string {
	return [...]string{"denied", "approved", "cache_hit"}[v]
}

// verdictOf maps a request's final state to ask's answer.
func verdictOf(st state) verdict {
	if st == approved || st == approvedAndCached {
		return verdictApproved
	}
	return verdictDenied
}

// A cached approval lapses once it goes cacheIdle without use, and never
// outlives cacheMax, however often it's used.
const (
	cacheIdle = 5 * time.Minute
	cacheMax  = time.Hour
)

type cachedApproval struct {
	by                   string // ID of the request whose tap created it
	approvedAt, lastUsed time.Time
}

// cacheKey joins the client's ID and args with NUL, which neither a hex ID
// nor an argument can contain, so two different requests never share a key.
func cacheKey(c client, args []string) string {
	return c.id + "\x00" + strings.Join(args, "\x00")
}

var errUnknownRequest = errors.New("unknown or expired request")

type approval struct {
	client  client
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
	names   *names        // names the IDs in a command for its page; nil looks nothing up

	mu   sync.Mutex
	reqs map[string]*approval
	// shortcut: entries are only removed when looked up, so commands that never
	// come back stay in memory; fine for one owner's taps, add a sweep if that changes.
	cache map[string]cachedApproval // by cacheKey
}

func newApprovals(baseURL string, notify func(context.Context, string) error) *approvals {
	return &approvals{baseURL: baseURL, notify: notify, keep: 10 * time.Minute, reqs: map[string]*approval{},
		cache: map[string]cachedApproval{}}
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ask answers from a cached approval of args if there is one. Otherwise it
// opens request id, sends the owner a link to its page, and waits for a
// decision or for ctx to end.
func (a *approvals) ask(ctx context.Context, id string, c client, args []string) (verdict, error) {
	if by, ok := a.cached(c, args); ok {
		trace.SpanFromContext(ctx).SetAttributes(attribute.String("op_gate.approved_by", by))
		slog.InfoContext(ctx, "cached approval used", "request_id", id, "approved_by", by)
		return verdictCacheHit, nil
	}

	r := &approval{client: c, args: args, state: pending, decided: make(chan state, 1)}
	a.mu.Lock()
	a.reqs[id] = r
	a.mu.Unlock()

	if err := a.notify(ctx, a.baseURL+"/approve/"+id); err != nil {
		a.decide(id, failed)
		return verdictDenied, fmt.Errorf("sending notification: %w", err)
	}
	// Warm the names while the notification reaches the phone, so the page needn't wait.
	go a.names.lines(context.WithoutCancel(ctx), id, args)

	select {
	case st := <-r.decided:
		return verdictOf(st), nil
	case <-ctx.Done():
		// A tap may have landed just before the deadline; the request's final
		// state decides, not which channel select happened to pick.
		if st, _ := a.decide(id, expired); st != expired {
			return verdictOf(st), nil
		}
		return verdictDenied, ctx.Err()
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
		if st == approvedAndCached {
			now := time.Now()
			a.cache[cacheKey(r.client, r.args)] = cachedApproval{by: id, approvedAt: now, lastUsed: now}
		}
		time.AfterFunc(a.keep, func() {
			a.mu.Lock()
			delete(a.reqs, id)
			a.mu.Unlock()
		})
	}
	return st, nil
}

// cached reports whether a fresh cached approval covers args from client c,
// and which request created it. A hit counts as a use; a stale entry is dropped.
func (a *approvals) cached(c client, args []string) (by string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := cacheKey(c, args)
	e, ok := a.cache[key]
	if !ok {
		return "", false
	}
	now := time.Now()
	if now.Sub(e.lastUsed) >= cacheIdle || now.Sub(e.approvedAt) >= cacheMax {
		delete(a.cache, key)
		return "", false
	}
	e.lastUsed = now
	a.cache[key] = e
	return e.by, true
}

// view returns request id's client, command, and state for its page.
func (a *approvals) view(id string) (client, []string, state, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.reqs[id]
	if !ok {
		return client{}, nil, 0, false
	}
	return r.client, r.args, r.state, true
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
