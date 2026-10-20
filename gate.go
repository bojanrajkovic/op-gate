package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

var tracer = otel.Tracer("github.com/bojanrajkovic/op-gate")

// The op-forward client gives up after OP_FORWARD_FETCH_TIMEOUT_MS plus 5s
// (305s with the recommended 300000) and then falls back to the local op. Both
// budgets together must stay inside that, or a late approval is wasted.
const (
	approvalTimeout = 4 * time.Minute
	opTimeout       = 30 * time.Second
)

// allowed maps each permitted op subcommand to its permitted second word.
// nil means the subcommand takes no second word (its next argument is data).
// The subcommand must be the first argument: flags before it are rejected,
// because telling a flag's value from a subcommand needs op's flag table.
var allowed = map[string][]string{
	"read":     nil,
	"whoami":   nil,
	"item":     {"get", "list"},
	"vault":    {"get", "list"},
	"document": {"get"},
}

func checkArgs(args []string) error {
	if len(args) == 0 {
		return errors.New("no command given")
	}
	verbs, ok := allowed[args[0]]
	if !ok {
		return fmt.Errorf("%q is not allowed", args[0])
	}
	if verbs != nil && (len(args) < 2 || !slices.Contains(verbs, args[1])) {
		return fmt.Errorf("%q is not allowed", strings.Join(args[:min(2, len(args))], " "))
	}
	return nil
}

// subcommand names the command for logs and spans without its arguments,
// which carry item and vault names.
func subcommand(args []string) string {
	if checkArgs(args) != nil {
		return "rejected"
	}
	if allowed[args[0]] == nil {
		return args[0]
	}
	return args[0] + " " + args[1]
}

// opRequest and result mirror op-forward's internal/executor Request and Result.
type opRequest struct {
	Args []string `json:"args"`
}

type result struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

func fail(format string, a ...any) result {
	return result{Stderr: "op-gate: " + fmt.Sprintf(format, a...) + "\n", ExitCode: 1}
}

type server struct {
	// ask blocks until the owner approves (true) or denies (false) request id,
	// or until ctx ends.
	ask             func(ctx context.Context, id string, args []string) (bool, error)
	run             func(ctx context.Context, args []string) result
	approvalTimeout time.Duration
	opTimeout       time.Duration
}

// handle returns the result to send back and a one-word outcome for the
// audit log. It never returns exit code 127: the op-forward shim reads 127 as
// "proxy unavailable" and silently runs the local op instead.
func (s *server) handle(ctx context.Context, id string, args []string) (result, string) {
	if err := checkArgs(args); err != nil {
		return fail("%v", err), "rejected"
	}

	actx, cancel := context.WithTimeout(ctx, s.approvalTimeout)
	defer cancel()
	approved, err := s.ask(actx, id, args)
	switch {
	case ctx.Err() != nil:
		return fail("client disconnected"), "disconnected"
	case errors.Is(err, context.DeadlineExceeded):
		return fail("no approval within %s", s.approvalTimeout), "timeout"
	case err != nil:
		return fail("%v", err), "error"
	case !approved:
		return fail("denied"), "denied"
	}

	rctx, cancel := context.WithTimeout(ctx, s.opTimeout)
	defer cancel()
	res := s.run(rctx, args)
	if res.ExitCode == 127 {
		res.ExitCode = 1
		res.Stderr = "op-gate: op exited 127\n" + res.Stderr
	}
	return res, "approved"
}

func (s *server) execute(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req opRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id := newID()
	ctx, span := tracer.Start(r.Context(), "op_gate.request")
	defer span.End()

	res, outcome := s.handle(ctx, id, req.Args)

	span.SetAttributes(
		attribute.String("op_gate.request_id", id),
		attribute.String("op_gate.subcommand", subcommand(req.Args)),
		attribute.String("op_gate.outcome", outcome),
		attribute.Int("op_gate.exit_code", res.ExitCode),
	)
	slog.InfoContext(ctx, "request", "request_id", id, "subcommand", subcommand(req.Args), "outcome", outcome,
		"exit_code", res.ExitCode, "duration", time.Since(start).Round(time.Millisecond).String())
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(res); err != nil {
		slog.WarnContext(ctx, "writing response", "request_id", id, "err", err)
	}
}

// runOp runs op with an environment holding only what op needs, so an
// approved command can never print op-gate's other configuration.
func runOp(ctx context.Context, args []string) result {
	ctx, span := tracer.Start(ctx, "op.run")
	defer span.End()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "op", args...)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"OP_SERVICE_ACCOUNT_TOKEN=" + os.Getenv("OP_SERVICE_ACCOUNT_TOKEN"),
	}
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = time.Second // don't wait on pipes held open by a killed op's children
	err := cmd.Run()

	res := result{Stdout: stdout.String(), Stderr: stderr.String()}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case ctx.Err() != nil:
		res.Stderr += "op-gate: op did not finish in time\n"
		res.ExitCode = 1
	case errors.As(err, &exitErr):
		res.ExitCode = exitErr.ExitCode()
	default:
		res.Stderr += fmt.Sprintf("op-gate: running op: %v\n", err)
		res.ExitCode = 1
	}

	span.SetAttributes(attribute.String("op_gate.subcommand", subcommand(args)), attribute.Int("op.exit_code", res.ExitCode))
	if res.ExitCode != 0 {
		span.SetStatus(codes.Error, "op failed")
	}
	return res
}
