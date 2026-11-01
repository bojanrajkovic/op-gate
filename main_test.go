package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"go.opentelemetry.io/otel"
)

func TestSetupTelemetry(t *testing.T) {
	t.Run("no endpoint leaves the global providers alone", func(t *testing.T) {
		t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
		mp, tp := otel.GetMeterProvider(), otel.GetTracerProvider()

		shutdown, err := setupTelemetry(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := shutdown(context.Background()); err != nil {
			t.Fatalf("shutdown = %v", err)
		}
		if otel.GetMeterProvider() != mp || otel.GetTracerProvider() != tp {
			t.Fatal("a global provider changed")
		}
	})

	t.Run("an endpoint exports runtime metrics on shutdown", func(t *testing.T) {
		var mu sync.Mutex
		bodies := map[string][]byte{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			defer mu.Unlock()
			bodies[r.URL.Path] = append(bodies[r.URL.Path], b...)
		}))
		defer srv.Close()
		t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)

		mp, tp := otel.GetMeterProvider(), otel.GetTracerProvider()
		t.Cleanup(func() {
			otel.SetMeterProvider(mp)
			otel.SetTracerProvider(tp)
		})

		shutdown, err := setupTelemetry(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := shutdown(context.Background()); err != nil {
			t.Fatalf("shutdown = %v", err)
		}

		mu.Lock()
		defer mu.Unlock()
		// The payload is uncompressed protobuf, so its strings appear verbatim.
		got := bodies["/v1/metrics"]
		for _, want := range []string{"op-gate", "go.goroutine.count", "go.memory.used"} {
			if !bytes.Contains(got, []byte(want)) {
				t.Errorf("metrics export has no %q", want)
			}
		}
	})
}
