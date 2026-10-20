package main

import (
	"context"
	"io"
	"log/slog"
	"strings"

	"go.opentelemetry.io/otel/trace"
)

// newLogger returns op-gate's JSON logger. Every line carries "service", and
// a line logged with a span's context carries its trace_id and span_id, so a
// log backend can link the line to its trace. Levels are lowercase ("info"),
// matching what most JSON loggers write, since pipelines often index them.
func newLogger(w io.Writer) *slog.Logger {
	lower := func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.LevelKey {
			a.Value = slog.StringValue(strings.ToLower(a.Value.String()))
		}
		return a
	}
	return slog.New(traceHandler{slog.NewJSONHandler(w, &slog.HandlerOptions{ReplaceAttr: lower})}).With("service", "op-gate")
}

// traceHandler adds the current span's IDs to each record.
type traceHandler struct{ slog.Handler }

func (h traceHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r.AddAttrs(slog.String("trace_id", sc.TraceID().String()), slog.String("span_id", sc.SpanID().String()))
	}
	return h.Handler.Handle(ctx, r)
}

func (h traceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return traceHandler{h.Handler.WithAttrs(attrs)}
}

func (h traceHandler) WithGroup(name string) slog.Handler {
	return traceHandler{h.Handler.WithGroup(name)}
}
