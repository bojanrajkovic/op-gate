package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckArgs(t *testing.T) {
	tests := []struct {
		args []string
		ok   bool
	}{
		{[]string{"read", "op://Agent/x/credential"}, true},
		{[]string{"whoami"}, true},
		{[]string{"item", "get", "x", "--vault", "Agent", "--format", "json"}, true},
		{[]string{"item", "list", "--vault", "Agent"}, true},
		{[]string{"vault", "list"}, true},
		{[]string{"vault", "get", "Agent"}, true},
		{[]string{"document", "get", "kubeconfig"}, true},
		{nil, false},
		{[]string{"run", "--", "env"}, false},
		{[]string{"inject", "-i", "tpl"}, false},
		{[]string{"signin"}, false},
		{[]string{"item", "create", "--title", "x"}, false},
		{[]string{"item", "edit", "x"}, false},
		{[]string{"item"}, false},
		{[]string{"document", "list"}, false},
		{[]string{"--account", "x", "signin"}, false},
		{[]string{"--format", "json", "item", "get", "x"}, false},
	}
	for _, tt := range tests {
		err := checkArgs(tt.args)
		if (err == nil) != tt.ok {
			t.Errorf("checkArgs(%q) = %v, want ok=%v", tt.args, err, tt.ok)
		}
	}
}

// fakeServer returns a server whose approver answers with decide and whose
// runner records whether op ran.
func fakeServer(decide func(ctx context.Context) (verdict, error), res result) (*server, *bool) {
	ran := new(bool)
	return &server{
		ask: func(ctx context.Context, _ string, _ []string) (verdict, error) { return decide(ctx) },
		run: func(context.Context, []string) result {
			*ran = true
			return res
		},
		approvalTimeout: 50 * time.Millisecond,
		opTimeout:       time.Second,
	}, ran
}

func TestHandle(t *testing.T) {
	approve := func(context.Context) (verdict, error) { return verdictApproved, nil }
	waitForCtx := func(ctx context.Context) (verdict, error) {
		<-ctx.Done()
		return verdictDenied, ctx.Err()
	}
	okArgs := []string{"read", "op://Agent/x/credential"}

	t.Run("approved runs op and passes output through", func(t *testing.T) {
		s, ran := fakeServer(approve, result{Stdout: "secret", Stderr: "warn", ExitCode: 3})
		res, outcome := s.handle(context.Background(), "req1", okArgs)
		if !*ran || outcome != "approved" || res != (result{Stdout: "secret", Stderr: "warn", ExitCode: 3}) {
			t.Fatalf("got %+v %q ran=%v", res, outcome, *ran)
		}
	})

	t.Run("denied", func(t *testing.T) {
		s, ran := fakeServer(func(context.Context) (verdict, error) { return verdictDenied, nil }, result{})
		res, outcome := s.handle(context.Background(), "req1", okArgs)
		if *ran || outcome != "denied" || res.ExitCode != 1 || !strings.Contains(res.Stderr, "denied") {
			t.Fatalf("got %+v %q ran=%v", res, outcome, *ran)
		}
	})

	t.Run("no approval in time", func(t *testing.T) {
		s, ran := fakeServer(waitForCtx, result{})
		res, outcome := s.handle(context.Background(), "req1", okArgs)
		if *ran || outcome != "timeout" || res.ExitCode != 1 {
			t.Fatalf("got %+v %q ran=%v", res, outcome, *ran)
		}
	})

	t.Run("client disconnects", func(t *testing.T) {
		s, ran := fakeServer(waitForCtx, result{})
		s.approvalTimeout = time.Minute
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, outcome := s.handle(ctx, "req1", okArgs)
		if *ran || outcome != "disconnected" {
			t.Fatalf("got %q ran=%v", outcome, *ran)
		}
	})

	t.Run("rejected command never asks", func(t *testing.T) {
		asked := false
		s, ran := fakeServer(func(context.Context) (verdict, error) { asked = true; return verdictApproved, nil }, result{})
		res, outcome := s.handle(context.Background(), "req1", []string{"run", "--", "env"})
		if asked || *ran || outcome != "rejected" || res.ExitCode != 1 {
			t.Fatalf("got %+v %q asked=%v ran=%v", res, outcome, asked, *ran)
		}
	})

	t.Run("op exit 127 becomes 1", func(t *testing.T) {
		s, _ := fakeServer(approve, result{Stderr: "boom\n", ExitCode: 127})
		res, _ := s.handle(context.Background(), "req1", okArgs)
		if res.ExitCode != 1 || !strings.HasPrefix(res.Stderr, "op-gate: op exited 127") {
			t.Fatalf("got %+v", res)
		}
	})
}

func TestExecuteEndpoint(t *testing.T) {
	s, _ := fakeServer(func(context.Context) (verdict, error) { return verdictApproved, nil }, result{Stdout: "ok"})
	req := httptest.NewRequest(http.MethodPost, "/op/execute", strings.NewReader(`{"args":["whoami"],"timeout_ms":300000}`))
	rec := httptest.NewRecorder()
	s.execute(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (anything else makes the client fall back to local op)", rec.Code)
	}
	var res result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || res.Stdout != "ok" {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
}

func TestRunOp(t *testing.T) {
	// A fake op that prints its environment and exits with the code in its first argument.
	dir := t.TempDir()
	script := "#!/bin/sh\nenv | sort\necho to-stderr >&2\nexit \"$1\"\n"
	if err := os.WriteFile(filepath.Join(dir, "op"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "sa-token")
	t.Setenv("HA_TOKEN_REF", "should-not-leak")

	res := runOp(context.Background(), []string{"7"})
	if res.ExitCode != 7 || res.Stderr != "to-stderr\n" {
		t.Fatalf("got %+v", res)
	}
	if !strings.Contains(res.Stdout, "OP_SERVICE_ACCOUNT_TOKEN=sa-token") || strings.Contains(res.Stdout, "HA_TOKEN_REF") {
		t.Fatalf("environment not scrubbed:\n%s", res.Stdout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := os.WriteFile(filepath.Join(dir, "op"), []byte("#!/bin/sh\nsleep 5\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if res := runOp(ctx, nil); res.ExitCode != 1 || !strings.Contains(res.Stderr, "did not finish") {
		t.Fatalf("timeout: got %+v", res)
	}
}
