package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

// pushover sends the approval link through the Pushover Message API.
type pushover struct {
	token, user string
	endpoint    string // https://api.pushover.net/1/messages.json
	client      *http.Client
}

// notify sends a generic message with link. The command stays off the
// message, because Pushover's servers would otherwise see item names; the
// approval page shows it. Priority 0 lets Quiet Hours silence it, and the
// ttl deletes it when the approval window closes.
func (p pushover) notify(ctx context.Context, link string) error {
	ctx, span := tracer.Start(ctx, "pushover.send")
	defer span.End()

	form := url.Values{
		"token":     {p.token},
		"user":      {p.user},
		"title":     {"op-gate"},
		"message":   {"An op command is waiting for your approval."},
		"url":       {link},
		"url_title": {"Review request"},
		"priority":  {"0"},
		"ttl":       {strconv.Itoa(int(approvalTimeout.Seconds()))},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.client.Do(req)
	if err != nil {
		span.SetStatus(codes.Error, "request failed")
		return fmt.Errorf("pushover: %w", err)
	}
	defer resp.Body.Close()

	var body struct {
		Status int      `json:"status"`
		Errors []string `json:"errors"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	span.SetAttributes(attribute.Int("http.response.status_code", resp.StatusCode))
	if err := json.Unmarshal(raw, &body); err != nil || body.Status != 1 {
		span.SetStatus(codes.Error, "rejected")
		return fmt.Errorf("pushover: HTTP %d: %s", resp.StatusCode, strings.Join(body.Errors, "; "))
	}
	return nil
}
