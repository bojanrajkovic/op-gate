package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
)

// newTestMeter returns the production MeterProvider setup with a reader the test collects by hand.
func newTestMeter() (*sdkmetric.MeterProvider, *sdkmetric.ManualReader) {
	reader := sdkmetric.NewManualReader()
	return newMeterProvider(reader, resource.Empty()), reader
}

func collect(t *testing.T, reader *sdkmetric.ManualReader, name string) (metricdata.Aggregation, bool) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				return m.Data, true
			}
		}
	}
	return nil, false
}

func TestRequestMetrics(t *testing.T) {
	const token = "junction:ssssssssssssssssssssssssssssssss"
	approve := func(context.Context) (verdict, error) { return verdictApproved, nil }
	deny := func(context.Context) (verdict, error) { return verdictDenied, nil }

	tests := []struct {
		name string
		ask  func(context.Context) (verdict, error)
		run  result
		body string
		auth string
		want attribute.Set
	}{
		{
			name: "op succeeds",
			ask:  approve,
			body: `{"args":["whoami"]}`,
			auth: "Bearer " + token,
			want: attribute.NewSet(attribute.String("outcome", "approved"), attribute.String("subcommand", "whoami"),
				attribute.Bool("op_failed", false), attribute.String("client_id", testClient.short())),
		},
		{
			name: "op exits non-zero",
			ask:  approve,
			run:  result{ExitCode: 3},
			body: `{"args":["item","get","x"]}`,
			auth: "Bearer " + token,
			want: attribute.NewSet(attribute.String("outcome", "approved"), attribute.String("subcommand", "item get"),
				attribute.Bool("op_failed", true), attribute.String("client_id", testClient.short())),
		},
		{
			name: "a denial exits non-zero but op never ran",
			ask:  deny,
			body: `{"args":["whoami"]}`,
			auth: "Bearer " + token,
			want: attribute.NewSet(attribute.String("outcome", "denied"), attribute.String("subcommand", "whoami"),
				attribute.Bool("op_failed", false), attribute.String("client_id", testClient.short())),
		},
		{
			name: "a rejected command hides its arguments",
			ask:  approve,
			body: `{"args":["run","--","env"]}`,
			auth: "Bearer " + token,
			want: attribute.NewSet(attribute.String("outcome", "rejected"), attribute.String("subcommand", "rejected"),
				attribute.Bool("op_failed", false), attribute.String("client_id", testClient.short())),
		},
		{
			name: "no client omits client_id",
			ask:  approve,
			body: `{"args":["whoami"]}`,
			auth: "Bearer placeholder",
			want: attribute.NewSet(attribute.String("outcome", "no_client"), attribute.String("subcommand", "whoami"),
				attribute.Bool("op_failed", false)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp, reader := newTestMeter()
			m, err := newRequestMetrics(mp)
			if err != nil {
				t.Fatal(err)
			}
			s, _ := fakeServer(tt.ask, tt.run)
			s.metrics = m

			req := httptest.NewRequest(http.MethodPost, "/op/execute", strings.NewReader(tt.body))
			req.Header.Set("Authorization", tt.auth)
			s.execute(httptest.NewRecorder(), req)

			data, ok := collect(t, reader, "op_gate.requests")
			if !ok {
				t.Fatal("no op_gate.requests")
			}
			count := data.(metricdata.Sum[int64])
			if !count.IsMonotonic || len(count.DataPoints) != 1 || count.DataPoints[0].Value != 1 {
				t.Fatalf("op_gate.requests = %+v", count)
			}
			if got := count.DataPoints[0].Attributes; !got.Equals(&tt.want) {
				t.Errorf("counter attributes = %v, want %v", got.Encoded(attribute.DefaultEncoder()), tt.want.Encoded(attribute.DefaultEncoder()))
			}

			data, ok = collect(t, reader, "op_gate.request.duration")
			if !ok {
				t.Fatal("no op_gate.request.duration")
			}
			hist, ok := data.(metricdata.ExponentialHistogram[float64])
			if !ok {
				t.Fatalf("op_gate.request.duration is %T, want an exponential histogram", data)
			}
			if len(hist.DataPoints) != 1 || hist.DataPoints[0].Count != 1 {
				t.Fatalf("op_gate.request.duration = %+v", hist)
			}
			if got := hist.DataPoints[0].Attributes; !got.Equals(&tt.want) {
				t.Errorf("histogram attributes = %v", got.Encoded(attribute.DefaultEncoder()))
			}
		})
	}
}

func TestRequestMetricsCountADisconnectedClient(t *testing.T) {
	mp, reader := newTestMeter()
	m, err := newRequestMetrics(mp)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s, _ := fakeServer(func(context.Context) (verdict, error) {
		cancel()
		return verdictDenied, context.Canceled
	}, result{})
	s.metrics = m

	req := httptest.NewRequest(http.MethodPost, "/op/execute", strings.NewReader(`{"args":["whoami"]}`)).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer junction:"+strings.Repeat("s", 32))
	s.execute(httptest.NewRecorder(), req)

	data, ok := collect(t, reader, "op_gate.requests")
	if !ok {
		t.Fatal("a disconnected client wasn't counted")
	}
	got := data.(metricdata.Sum[int64]).DataPoints[0].Attributes
	if v, _ := got.Value("outcome"); v.AsString() != "disconnected" {
		t.Fatalf("outcome = %q", v.AsString())
	}
}

func gauge(t *testing.T, reader *sdkmetric.ManualReader, name string) int64 {
	t.Helper()
	data, ok := collect(t, reader, name)
	if !ok {
		t.Fatalf("no %s", name)
	}
	points := data.(metricdata.Gauge[int64]).DataPoints
	if len(points) != 1 {
		t.Fatalf("%s has %d points, want 1", name, len(points))
	}
	return points[0].Value
}

func TestApprovalGauges(t *testing.T) {
	args := []string{"read", "op://Agent/x/credential"}

	t.Run("pending counts only undecided requests", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			mp, reader := newTestMeter()
			a, links := newTestApprovals(nil)
			if err := a.observe(mp); err != nil {
				t.Fatal(err)
			}
			if got := gauge(t, reader, "op_gate.approvals.pending"); got != 0 {
				t.Fatalf("pending with no requests = %d", got)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go a.ask(ctx, "waiting", testClient, args)
			<-links
			if got := gauge(t, reader, "op_gate.approvals.pending"); got != 1 {
				t.Fatalf("pending with one waiting = %d", got)
			}

			if _, err := a.decide("waiting", denied); err != nil {
				t.Fatal(err)
			}
			if _, _, _, ok := a.view("waiting"); !ok {
				t.Fatal("the finished request should still be held for its page")
			}
			if got := gauge(t, reader, "op_gate.approvals.pending"); got != 0 {
				t.Fatalf("pending after a decision = %d", got)
			}
		})
	})

	t.Run("cache entries count only fresh approvals", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			mp, reader := newTestMeter()
			a, links := newTestApprovals(nil)
			if err := a.observe(mp); err != nil {
				t.Fatal(err)
			}

			approveVia(t, a, links, "req1", args, approvedAndCached)
			if got := gauge(t, reader, "op_gate.cache.entries"); got != 1 {
				t.Fatalf("entries after caching = %d", got)
			}

			time.Sleep(cacheIdle)
			if got := gauge(t, reader, "op_gate.cache.entries"); got != 0 {
				t.Fatalf("entries after going idle = %d", got)
			}
		})
	})
}
