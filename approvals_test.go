package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"testing/synctest"
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
		go a.ask(context.Background(), "req2", testClient, args)
		if got := <-links; got != "https://op-gate.example/approve/req2" {
			t.Fatalf("link = %q", got)
		}
		a.decide("req2", denied)
	})

	t.Run("approve", func(t *testing.T) {
		a, links := newTestApprovals(nil)
		decideAfterNotify(a, links, approved)
		if v, err := a.ask(context.Background(), "req1", testClient, args); v != verdictApproved || err != nil {
			t.Fatalf("ask = %v, %v", v, err)
		}
		if _, _, st, _ := a.view("req1"); st != approved {
			t.Fatalf("page state = %v", st)
		}
	})

	t.Run("deny", func(t *testing.T) {
		a, links := newTestApprovals(nil)
		decideAfterNotify(a, links, denied)
		if v, err := a.ask(context.Background(), "req1", testClient, args); v != verdictDenied || err != nil {
			t.Fatalf("ask = %v, %v", v, err)
		}
	})

	t.Run("timeout expires the page", func(t *testing.T) {
		a, _ := newTestApprovals(nil)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if _, err := a.ask(ctx, "req1", testClient, args); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", err)
		}
		if _, _, st, _ := a.view("req1"); st != expired {
			t.Fatalf("page state = %v, want expired", st)
		}
		if st, _ := a.decide("req1", approved); st != expired {
			t.Fatal("an expired request was approved")
		}
	})

	t.Run("failed notification fails the request", func(t *testing.T) {
		a, _ := newTestApprovals(errors.New("pushover down"))
		if _, err := a.ask(context.Background(), "req1", testClient, args); err == nil {
			t.Fatal("ask succeeded without a notification")
		}
		if _, _, st, _ := a.view("req1"); st != failed {
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
		if v, _ := a.ask(ctx, "req1", testClient, args); v != verdictApproved {
			t.Fatal("approval lost to a simultaneous cancel")
		}
	})

	t.Run("a cached approval that wins the race with the deadline counts", func(t *testing.T) {
		a, links := newTestApprovals(nil)
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-links
			a.decide("req1", approvedAndCached)
			cancel()
		}()
		if v, _ := a.ask(ctx, "req1", testClient, args); v != verdictApproved {
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
		a.ask(context.Background(), "req1", testClient, args)
		time.Sleep(50 * time.Millisecond)
		if _, _, _, ok := a.view("req1"); ok {
			t.Fatal("final request kept forever")
		}
	})
}

// approveVia runs ask for id and answers its notification with to.
func approveVia(t *testing.T, a *approvals, links chan string, id string, args []string, to state) {
	t.Helper()
	go func() {
		<-links
		a.decide(id, to)
	}()
	if v, err := a.ask(context.Background(), id, testClient, args); v != verdictApproved || err != nil {
		t.Fatalf("ask = %v, %v", v, err)
	}
}

// notifies reports whether ask for id sent a notification, denying it if so.
func notifies(a *approvals, links chan string, id string, c client, args []string) bool {
	done := make(chan verdict, 1)
	go func() {
		v, _ := a.ask(context.Background(), id, c, args)
		done <- v
	}()
	select {
	case <-links:
		a.decide(id, denied)
		<-done
		return true
	case <-done:
		return false
	}
}

func TestCache(t *testing.T) {
	args := []string{"read", "op://Agent/x/credential"}

	t.Run("a cached approval skips the phone", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, links := newTestApprovals(nil)
			approveVia(t, a, links, "req1", args, approvedAndCached)
			if v, err := a.ask(context.Background(), "req2", testClient, args); v != verdictCacheHit || err != nil {
				t.Fatalf("ask = %v, %v", v, err)
			}
			if len(links) != 0 {
				t.Fatal("a cache hit sent a notification")
			}
			if _, _, _, ok := a.view("req2"); ok {
				t.Fatal("a cache hit opened an approval page")
			}
		})
	})

	t.Run("plain approve doesn't cache", func(t *testing.T) {
		a, links := newTestApprovals(nil)
		approveVia(t, a, links, "req1", args, approved)
		if !notifies(a, links, "req2", testClient, args) {
			t.Fatal("a one-time approval was reused")
		}
	})

	t.Run("only the exact arguments match", func(t *testing.T) {
		a, links := newTestApprovals(nil)
		approveVia(t, a, links, "req1", args, approvedAndCached)
		if !notifies(a, links, "req2", testClient, append(args, "--no-newline")) {
			t.Fatal("different arguments used the cached approval")
		}
		// NUL joins the key, so regrouping the same words is a different command.
		if !notifies(a, links, "req3", testClient, []string{"read", "op://Agent/x/credential --no-newline"}) {
			t.Fatal("regrouped arguments used the cached approval")
		}
	})

	t.Run("another client's cached approval doesn't apply", func(t *testing.T) {
		a, links := newTestApprovals(nil)
		approveVia(t, a, links, "req1", args, approvedAndCached)
		if !notifies(a, links, "req2", otherClient, args) {
			t.Fatal("a different client used the cached approval")
		}
	})

	t.Run("lapses after going unused", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, links := newTestApprovals(nil)
			approveVia(t, a, links, "req1", args, approvedAndCached)
			time.Sleep(cacheIdle)
			if !notifies(a, links, "req2", testClient, args) {
				t.Fatal("cached approval outlived its idle timeout")
			}
		})
	})

	t.Run("use keeps it alive, up to the cap", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, links := newTestApprovals(nil)
			approveVia(t, a, links, "req1", args, approvedAndCached)
			start := time.Now()
			for time.Since(start)+4*time.Minute < cacheMax {
				time.Sleep(4 * time.Minute)
				if v, _ := a.ask(context.Background(), "hit", testClient, args); v != verdictCacheHit {
					t.Fatalf("miss after %v of steady use", time.Since(start))
				}
			}
			time.Sleep(cacheMax - time.Since(start))
			if !notifies(a, links, "req2", testClient, args) {
				t.Fatal("cached approval outlived its cap")
			}
		})
	})

	t.Run("a tap on an expired request caches nothing", func(t *testing.T) {
		a, links := newTestApprovals(nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		a.ask(ctx, "req1", testClient, args)
		<-links
		if st, _ := a.decide("req1", approvedAndCached); st != expired {
			t.Fatalf("state = %v", st)
		}
		if !notifies(a, links, "req2", testClient, args) {
			t.Fatal("a late tap cached an approval")
		}
	})

	t.Run("a hit logs which request approved it", func(t *testing.T) {
		var buf bytes.Buffer
		old := slog.Default()
		slog.SetDefault(newLogger(&buf))
		t.Cleanup(func() { slog.SetDefault(old) })

		a, links := newTestApprovals(nil)
		approveVia(t, a, links, "req1", args, approvedAndCached)
		a.ask(context.Background(), "req2", testClient, args)

		var line map[string]any
		if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
			t.Fatalf("log %q: %v", buf.String(), err)
		}
		if line["msg"] != "cached approval used" || line["request_id"] != "req2" || line["approved_by"] != "req1" {
			t.Fatalf("log line = %v", line)
		}
	})
}

func TestAskWarmsNames(t *testing.T) {
	// An unknown item makes every lookup want a refresh once 30s pass.
	args := []string{"read", "op://" + agentsID + "/" + unknown + "/credential"}
	synctest.Test(t, func(t *testing.T) {
		a, links := newTestApprovals(nil)
		n, calls := countingNames(func() (snapshot, error) { return testSnapshot, nil })
		a.names = n
		approveVia(t, a, links, "req1", args, approvedAndCached)
		synctest.Wait()
		if *calls != 1 {
			t.Fatalf("a new request looked names up %d times", *calls)
		}
		time.Sleep(namesRetry)
		a.ask(context.Background(), "req2", testClient, args)
		synctest.Wait()
		if *calls != 1 {
			t.Fatal("a cache hit looked names up")
		}
	})
}
