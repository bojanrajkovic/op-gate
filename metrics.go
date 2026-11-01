package main

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const meterName = "github.com/bojanrajkovic/op-gate"

// requestMetrics counts and times requests. A nil *requestMetrics records nothing.
type requestMetrics struct {
	count    metric.Int64Counter
	duration metric.Float64Histogram
}

func newRequestMetrics(mp metric.MeterProvider) (*requestMetrics, error) {
	meter := mp.Meter(meterName)
	count, err := meter.Int64Counter("op_gate.requests",
		metric.WithUnit("{request}"), metric.WithDescription("Requests handled, by how they ended."))
	if err != nil {
		return nil, err
	}
	duration, err := meter.Float64Histogram("op_gate.request.duration",
		metric.WithUnit("s"), metric.WithDescription("Time to handle a request, including the approval wait and the op run."))
	if err != nil {
		return nil, err
	}
	return &requestMetrics{count: count, duration: duration}, nil
}

// record adds one finished request. An empty clientID leaves client_id off.
func (m *requestMetrics) record(ctx context.Context, outcome, subcommand string, opFailed bool, clientID string, d time.Duration) {
	if m == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("outcome", outcome),
		attribute.String("subcommand", subcommand),
		attribute.Bool("op_failed", opFailed),
	}
	if clientID != "" {
		attrs = append(attrs, attribute.String("client_id", clientID))
	}
	set := metric.WithAttributes(attrs...)
	m.count.Add(ctx, 1, set)
	m.duration.Record(ctx, d.Seconds(), set)
}

// observe reports the pending requests and fresh cached approvals at each metric export.
func (a *approvals) observe(mp metric.MeterProvider) error {
	meter := mp.Meter(meterName)
	pendingGauge, err := meter.Int64ObservableGauge("op_gate.approvals.pending",
		metric.WithUnit("{request}"), metric.WithDescription("Requests waiting on the owner."))
	if err != nil {
		return err
	}
	cacheGauge, err := meter.Int64ObservableGauge("op_gate.cache.entries",
		metric.WithUnit("{entry}"), metric.WithDescription("Cached approvals that would still allow a command."))
	if err != nil {
		return err
	}
	_, err = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		waiting, entries := a.counts()
		o.ObserveInt64(pendingGauge, int64(waiting))
		o.ObserveInt64(cacheGauge, int64(entries))
		return nil
	}, pendingGauge, cacheGauge)
	return err
}

// counts returns how many requests are pending and how many cached approvals
// are fresh. Finished requests and stale entries stay in the maps for a while,
// so their lengths would overcount.
func (a *approvals) counts() (waiting, entries int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, r := range a.reqs {
		if r.state == pending {
			waiting++
		}
	}
	now := time.Now()
	for _, e := range a.cache {
		if e.fresh(now) {
			entries++
		}
	}
	return waiting, entries
}
