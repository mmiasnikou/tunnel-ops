package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func sampleResults() []Result {
	ts := time.Date(2026, 7, 28, 6, 0, 0, 0, time.UTC)
	return []Result{
		{
			Target:    Target{Name: "de-01", Addr: "203.0.113.10:443", SNI: "www.microsoft.com", Provider: "hetzner"},
			OK:        true,
			TCPOK:     true,
			TLSOK:     true,
			TLSTime:   0.0425,
			Timestamp: ts,
		},
		{
			Target:    Target{Name: "nl-02", Addr: "203.0.113.11:443", SNI: "www.microsoft.com"},
			TCPOK:     true,
			Error:     "tls: handshake failure",
			Timestamp: ts,
		},
		{
			Target:    Target{Name: "fi-03", Addr: "203.0.113.12:443", SNI: "www.microsoft.com"},
			Error:     "tcp: i/o timeout",
			Timestamp: ts,
		},
	}
}

func TestBuildPayloadMapsPhases(t *testing.T) {
	p := buildPayload("run-1", "pytest", time.Now().UTC(), sampleResults())

	if len(p.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(p.Results))
	}

	up := p.Results[0]
	if up.FailedPhase != "" {
		t.Errorf("healthy node should have no failed phase, got %q", up.FailedPhase)
	}
	if up.LatencyMS == nil || *up.LatencyMS < 42 || *up.LatencyMS > 43 {
		t.Errorf("expected latency around 42.5ms, got %v", up.LatencyMS)
	}

	if got := p.Results[1].FailedPhase; got != "tls" {
		t.Errorf("TCP up, TLS down should report phase tls, got %q", got)
	}
	if p.Results[1].LatencyMS != nil {
		t.Error("a failed handshake must not report a latency")
	}

	if got := p.Results[2].FailedPhase; got != "tcp" {
		t.Errorf("TCP down should report phase tcp, got %q", got)
	}
}

func TestPushSendsBearerAndValidJSON(t *testing.T) {
	var gotAuth string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	payload := buildPayload("run-1", "test", time.Now().UTC(), sampleResults())
	err := pushResults(context.Background(), srv.Client(), srv.URL, "secret-token", payload)
	if err != nil {
		t.Fatalf("push failed: %v", err)
	}

	if gotAuth != "Bearer secret-token" {
		t.Errorf("unexpected auth header: %q", gotAuth)
	}

	var decoded map[string]any
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("server received invalid JSON: %v", err)
	}
	if decoded["run_id"] != "run-1" {
		t.Errorf("run_id not propagated: %v", decoded["run_id"])
	}
}

func TestPushRetriesServerErrors(t *testing.T) {
	var calls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	payload := buildPayload("run-2", "test", time.Now().UTC(), sampleResults())
	if err := pushResults(context.Background(), srv.Client(), srv.URL, "", payload); err != nil {
		t.Fatalf("push should have recovered on retry: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("expected 2 attempts, got %d", got)
	}
}

func TestPushDoesNotRetryRejectedToken(t *testing.T) {
	var calls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	payload := buildPayload("run-3", "test", time.Now().UTC(), sampleResults())
	err := pushResults(context.Background(), srv.Client(), srv.URL, "wrong", payload)
	if err == nil {
		t.Fatal("expected an error on 401")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("a rejected token must not be retried, got %d attempts", got)
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Errorf("error should explain the rejection, got %v", err)
	}
}

func TestNewUUIDv4Format(t *testing.T) {
	id, err := newUUIDv4()
	if err != nil {
		t.Fatalf("uuid generation failed: %v", err)
	}

	parts := strings.Split(id, "-")
	if len(parts) != 5 {
		t.Fatalf("expected 5 dash-separated groups, got %q", id)
	}
	if lens := []int{8, 4, 4, 4, 12}; func() bool {
		for i, want := range lens {
			if len(parts[i]) != want {
				return true
			}
		}
		return false
	}() {
		t.Errorf("unexpected group lengths in %q", id)
	}
	if parts[2][0] != '4' {
		t.Errorf("version nibble should be 4, got %q", id)
	}
	if !strings.ContainsRune("89ab", rune(parts[3][0])) {
		t.Errorf("variant nibble should be 8-b, got %q", id)
	}

	other, _ := newUUIDv4()
	if id == other {
		t.Error("two generated ids must not collide")
	}
}
