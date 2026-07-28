package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// This file adds the -push-url path: after probing, ship the batch to a
// probestore instance so the results become history instead of a one-shot
// answer on stdout.
//
// The wire format is owned by probestore, not by Result, so the payload gets
// its own types. Marshalling Result directly would weld the JSON that humans
// read on stdout to the JSON the service ingests, and neither could then
// change without breaking the other.

type pushNode struct {
	Name     string `json:"name"`
	Addr     string `json:"addr"`
	SNI      string `json:"sni"`
	Provider string `json:"provider,omitempty"`
}

type pushResult struct {
	Node  pushNode  `json:"node"`
	TS    time.Time `json:"ts"`
	TCPOK bool      `json:"tcp_ok"`
	TLSOK bool      `json:"tls_ok"`

	// A pointer so an unsuccessful handshake omits the field entirely rather
	// than reporting a latency of zero, which would be a lie a dashboard
	// happily averages in.
	LatencyMS   *float64 `json:"latency_ms,omitempty"`
	Error       string   `json:"error,omitempty"`
	FailedPhase string   `json:"failed_phase,omitempty"`
}

type pushPayload struct {
	RunID     string       `json:"run_id"`
	Source    string       `json:"source"`
	StartedAt time.Time    `json:"started_at"`
	Results   []pushResult `json:"results"`
}

// newUUIDv4 builds a random run id without pulling in a dependency — the
// whole tool is standard library only, and a UUID is sixteen random bytes
// with six bits pinned by RFC 4122.
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating run id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// failedPhase names the phase that broke, or "" when the node is healthy.
func failedPhase(r Result) string {
	switch {
	case !r.TCPOK:
		return "tcp"
	case !r.TLSOK:
		return "tls"
	default:
		return ""
	}
}

func buildPayload(runID, source string, startedAt time.Time, results []Result) pushPayload {
	out := make([]pushResult, 0, len(results))
	for _, r := range results {
		pr := pushResult{
			Node: pushNode{
				Name:     r.Name,
				Addr:     r.Addr,
				SNI:      r.SNI,
				Provider: r.Provider,
			},
			TS:          r.Timestamp,
			TCPOK:       r.TCPOK,
			TLSOK:       r.TLSOK,
			Error:       r.Error,
			FailedPhase: failedPhase(r),
		}
		if r.TLSOK {
			ms := r.TLSTime * 1000
			pr.LatencyMS = &ms
		}
		out = append(out, pr)
	}

	return pushPayload{
		RunID:     runID,
		Source:    source,
		StartedAt: startedAt,
		Results:   out,
	}
}

// pushResults POSTs one batch, retrying transient failures.
//
// Retrying is only safe because probestore keys ingestion on run_id: the same
// payload sent twice is stored once. The retry loop and that key are one
// design, not two.
func pushResults(ctx context.Context, client *http.Client, url, token string, payload pushPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encoding payload: %w", err)
	}

	// Attempt immediately, then after 1s and 3s. A prober that gives up on the
	// first refused connection loses the very outage it was built to record.
	backoff := []time.Duration{0, time.Second, 3 * time.Second}

	var lastErr error
	for attempt, wait := range backoff {
		if wait > 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		err := postOnce(ctx, client, url, token, body)
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("attempt %d: %w", attempt+1, err)

		// A rejected token or a malformed body will be rejected identically
		// next time, so only transient failures are worth another round trip.
		var perm permanentError
		if errors.As(err, &perm) {
			return lastErr
		}
	}
	return lastErr
}

// permanentError marks a response that retrying cannot fix (4xx).
type permanentError struct{ msg string }

func (e permanentError) Error() string { return e.msg }

func postOnce(ctx context.Context, client *http.Client, url, token string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return permanentError{msg: "building request: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("posting to %s: %w", url, err)
	}
	defer resp.Body.Close()

	// Drain before closing so the connection can be reused by keep-alive.
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return permanentError{
			msg: fmt.Sprintf("server rejected the batch: %s: %s", resp.Status, bytes.TrimSpace(snippet)),
		}
	default:
		return fmt.Errorf("server error: %s: %s", resp.Status, bytes.TrimSpace(snippet))
	}
}
