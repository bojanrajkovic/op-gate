// Command op-gate runs 1Password CLI commands for op-forward clients after
// its owner approves each one with a passkey on their phone.
//
// It speaks op-forward's wire protocol (POST /op/execute), so an unmodified
// op-forward shim reaches it by setting OP_FORWARD_ADDR. Each request sends
// a Pushover notification linking to an approval page, where Approve needs a
// passkey with Face ID. See README.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.28.0"
)

func quoteArgs(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\"'") {
			a = strconv.Quote(a)
		}
		q[i] = a
	}
	return strings.Join(q, " ")
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("missing required environment variable", "name", key)
		os.Exit(1)
	}
	return v
}

// readSecret reads an op:// reference with op-gate's service account.
func readSecret(ctx context.Context, ref string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	res := runOp(ctx, []string{"read", ref})
	if res.ExitCode != 0 {
		return "", fmt.Errorf("reading %s: %s", ref, strings.TrimSpace(res.Stderr))
	}
	return strings.TrimSpace(res.Stdout), nil
}

// setupTelemetry exports spans and Go runtime metrics over OTLP/HTTP when
// OTEL_EXPORTER_OTLP_ENDPOINT is set, and leaves OpenTelemetry's no-op providers
// in place otherwise. The func it returns shuts down both providers.
func setupTelemetry(ctx context.Context) (func(context.Context) error, error) {
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" {
		return func(context.Context) error { return nil }, nil
	}
	traceExp, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("trace exporter: %w", err)
	}
	metricExp, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("metric exporter: %w", err)
	}
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(semconv.ServiceName("op-gate")))
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(traceExp), sdktrace.WithResource(res))
	mp := newMeterProvider(sdkmetric.NewPeriodicReader(metricExp), res)
	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) { slog.Warn("otel", "err", err) }))
	if err := runtime.Start(runtime.WithMeterProvider(mp)); err != nil {
		return nil, fmt.Errorf("runtime metrics: %w", err)
	}
	return func(ctx context.Context) error { return errors.Join(tp.Shutdown(ctx), mp.Shutdown(ctx)) }, nil
}

// newMeterProvider stores request durations as an exponential histogram, which
// covers quick cache hits and long approval waits without chosen buckets.
func newMeterProvider(reader sdkmetric.Reader, res *resource.Resource) *sdkmetric.MeterProvider {
	duration := sdkmetric.NewView(
		sdkmetric.Instrument{Name: "op_gate.request.duration"},
		sdkmetric.Stream{Aggregation: sdkmetric.AggregationBase2ExponentialHistogram{MaxSize: 160, MaxScale: 20}},
	)
	return sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader), sdkmetric.WithResource(res), sdkmetric.WithView(duration))
}

func main() {
	slog.SetDefault(newLogger(os.Stdout))
	if err := run(); err != nil {
		slog.Error("op-gate stopped", "err", err)
		os.Exit(1)
	}
}

func run() error {
	mustEnv("OP_SERVICE_ACCOUNT_TOKEN")
	approvalURL := strings.TrimSuffix(mustEnv("APPROVAL_URL"), "/") // e.g. https://op-gate.example.com
	passkeyDir := mustEnv("PASSKEYS_DIR")                           // registered passkeys, one per file
	tokenRef := mustEnv("PUSHOVER_TOKEN_REF")                       // op:// reference to the Pushover app token
	userRef := mustEnv("PUSHOVER_USER_REF")                         // op:// reference to the approver's Pushover user key
	opAddr := envOr("LISTEN_ADDR", ":18340")
	webAddr := envOr("APPROVAL_LISTEN_ADDR", ":8080")

	ctx := context.Background()
	shutdown, err := setupTelemetry(ctx)
	if err != nil {
		return err
	}
	defer shutdown(context.Background())

	creds, err := loadPasskeys(passkeyDir)
	if err != nil {
		return err
	}
	keys, err := newPasskeys(approvalURL, creds)
	if err != nil {
		return err
	}
	token, err := readSecret(ctx, tokenRef)
	if err != nil {
		return err
	}
	user, err := readSecret(ctx, userRef)
	if err != nil {
		return err
	}
	push := pushover{token: token, user: user, endpoint: "https://api.pushover.net/1/messages.json",
		client: &http.Client{Timeout: 15 * time.Second}}

	a := newApprovals(approvalURL, push.notify)
	a.nameCache = &nameCache{list: func(ctx context.Context) (snapshot, error) { return listNames(ctx, runOp) }}
	if err := a.observe(otel.GetMeterProvider()); err != nil {
		return fmt.Errorf("approval metrics: %w", err)
	}
	metrics, err := newRequestMetrics(otel.GetMeterProvider())
	if err != nil {
		return fmt.Errorf("request metrics: %w", err)
	}
	s := &server{ask: a.ask, run: runOp, approvalTimeout: approvalTimeout, opTimeout: opTimeout, metrics: metrics}

	// Two listeners, one job each: op-forward's protocol, and the approval
	// pages, which must be served over HTTPS by a TLS-terminating proxy.
	opMux := http.NewServeMux()
	opMux.HandleFunc("POST /op/execute", s.execute)
	opMux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	opSrv := &http.Server{Addr: opAddr, Handler: opMux, ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout: approvalTimeout + opTimeout + 30*time.Second}
	webSrv := &http.Server{Addr: webAddr, Handler: newWeb(a, keys).handler(), ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout: 30 * time.Second}

	slog.Info("listening", "op_addr", opAddr, "approval_addr", webAddr, "passkeys", len(creds))
	errc := make(chan error, 2)
	go func() { errc <- opSrv.ListenAndServe() }()
	go func() { errc <- webSrv.ListenAndServe() }()
	err = <-errc
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
