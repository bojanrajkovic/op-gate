package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestPushover(t *testing.T) {
	t.Run("sends a generic message with the link", func(t *testing.T) {
		var got url.Values
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.ParseForm()
			got = r.PostForm
			w.Write([]byte(`{"status":1,"request":"abc"}`))
		}))
		defer srv.Close()

		p := pushover{token: "app-token", user: "user-key", endpoint: srv.URL, client: srv.Client()}
		if err := p.notify(context.Background(), "https://op-gate.example/approve/req1"); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{
			"token": "app-token", "user": "user-key",
			"url":      "https://op-gate.example/approve/req1",
			"priority": "0", "ttl": "240",
		}
		for k, v := range want {
			if got.Get(k) != v {
				t.Errorf("%s = %q, want %q", k, got.Get(k), v)
			}
		}
		// The message must not carry the command: Pushover's servers would see item names.
		if strings.Contains(got.Get("message"), "op://") {
			t.Errorf("message leaks the command: %q", got.Get("message"))
		}
	})

	t.Run("surfaces Pushover's error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"status":0,"errors":["application token is invalid"]}`))
		}))
		defer srv.Close()

		p := pushover{token: "bad", user: "u", endpoint: srv.URL, client: srv.Client()}
		err := p.notify(context.Background(), "https://x")
		if err == nil || !strings.Contains(err.Error(), "application token is invalid") {
			t.Fatalf("err = %v", err)
		}
	})
}
