package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSettle(t *testing.T) {
	for _, from := range []state{approved, denied, expired, failed} {
		for _, to := range []state{approved, denied, expired, failed} {
			if got, moved := settle(from, to); moved || got != from {
				t.Errorf("settle(%v, %v) = %v, %v; a final state must not change", from, to, got, moved)
			}
		}
	}
	for _, to := range []state{approved, denied, expired, failed} {
		if got, moved := settle(pending, to); !moved || got != to {
			t.Errorf("settle(pending, %v) = %v, %v", to, got, moved)
		}
	}
}

// newTestApprovals returns approvals whose notifications are recorded on links.
func newTestApprovals(notifyErr error) (*approvals, chan string) {
	links := make(chan string, 4)
	a := newApprovals("https://op-gate.example", func(_ context.Context, link string) error {
		links <- link
		return notifyErr
	})
	return a, links
}

func TestAsk(t *testing.T) {
	args := []string{"read", "op://Agent/x/credential"}

	decideAfterNotify := func(a *approvals, links chan string, to state) {
		go func() {
			<-links
			if _, err := a.decide("req1", to); err != nil {
				panic(err)
			}
		}()
	}

	t.Run("notification links to the request's page", func(t *testing.T) {
		a, links := newTestApprovals(nil)
		go a.ask(context.Background(), "req2", args)
		if got := <-links; got != "https://op-gate.example/approve/req2" {
			t.Fatalf("link = %q", got)
		}
		a.decide("req2", denied)
	})

	t.Run("approve", func(t *testing.T) {
		a, links := newTestApprovals(nil)
		decideAfterNotify(a, links, approved)
		if v, err := a.ask(context.Background(), "req1", args); v != verdictApproved || err != nil {
			t.Fatalf("ask = %v, %v", v, err)
		}
		if _, st, _ := a.view("req1"); st != approved {
			t.Fatalf("page state = %v", st)
		}
	})

	t.Run("deny", func(t *testing.T) {
		a, links := newTestApprovals(nil)
		decideAfterNotify(a, links, denied)
		if v, err := a.ask(context.Background(), "req1", args); v != verdictDenied || err != nil {
			t.Fatalf("ask = %v, %v", v, err)
		}
	})

	t.Run("timeout expires the page", func(t *testing.T) {
		a, _ := newTestApprovals(nil)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if _, err := a.ask(ctx, "req1", args); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", err)
		}
		if _, st, _ := a.view("req1"); st != expired {
			t.Fatalf("page state = %v, want expired", st)
		}
		if st, _ := a.decide("req1", approved); st != expired {
			t.Fatal("an expired request was approved")
		}
	})

	t.Run("failed notification fails the request", func(t *testing.T) {
		a, _ := newTestApprovals(errors.New("pushover down"))
		if _, err := a.ask(context.Background(), "req1", args); err == nil {
			t.Fatal("ask succeeded without a notification")
		}
		if _, st, _ := a.view("req1"); st != failed {
			t.Fatalf("page state = %v, want failed", st)
		}
	})

	t.Run("a tap that wins the race with the deadline counts", func(t *testing.T) {
		a, links := newTestApprovals(nil)
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-links
			a.decide("req1", approved)
			cancel()
		}()
		// Either branch of ask's select may fire; both must report the approval.
		if v, _ := a.ask(ctx, "req1", args); v != verdictApproved {
			t.Fatal("approval lost to a simultaneous cancel")
		}
	})

	t.Run("unknown request", func(t *testing.T) {
		a, _ := newTestApprovals(nil)
		if _, err := a.decide("nope", approved); !errors.Is(err, errUnknownRequest) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("final pages are forgotten after a while", func(t *testing.T) {
		a, links := newTestApprovals(nil)
		a.keep = 10 * time.Millisecond
		decideAfterNotify(a, links, denied)
		a.ask(context.Background(), "req1", args)
		time.Sleep(50 * time.Millisecond)
		if _, _, ok := a.view("req1"); ok {
			t.Fatal("final request kept forever")
		}
	})
}
