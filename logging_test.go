package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestLogsCarryTraceIDs(t *testing.T) {
	var buf bytes.Buffer
	log := newLogger(&buf)

	ctx, span := sdktrace.NewTracerProvider().Tracer("test").Start(context.Background(), "request")
	log.InfoContext(ctx, "request", "request_id", "req1")
	span.End()
	log.Info("no span")

	dec := json.NewDecoder(&buf)
	var withSpan, without map[string]any
	if err := dec.Decode(&withSpan); err != nil {
		t.Fatal(err)
	}
	if err := dec.Decode(&without); err != nil {
		t.Fatal(err)
	}

	sc := span.SpanContext()
	if withSpan["trace_id"] != sc.TraceID().String() || withSpan["span_id"] != sc.SpanID().String() {
		t.Errorf("line in a span = %v, want trace_id %s and span_id %s", withSpan, sc.TraceID(), sc.SpanID())
	}
	if withSpan["level"] != "info" {
		t.Errorf("level = %v, want lowercase info", withSpan["level"])
	}
	if withSpan["service"] != "op-gate" || without["service"] != "op-gate" {
		t.Errorf("service missing: %v / %v", withSpan, without)
	}
	if _, ok := without["trace_id"]; ok {
		t.Errorf("line outside a span has a trace_id: %v", without)
	}
}
