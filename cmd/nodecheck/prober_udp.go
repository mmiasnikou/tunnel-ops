package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// udpProber is the protocol-agnostic UDP probe: send some bytes, accept any
// datagram back as proof of life. It exists both as a useful check for simple
// request/response services and as the first non-TLS user of the abstraction.
//
// Its two phases are the UDP analogue of tcp/tls, but the reachability half is
// much weaker and it is worth being honest about why. net.Dial on UDP sends
// nothing — it only binds a socket and fixes the peer address — and a Write
// hands the datagram to the kernel without waiting for anything. So the "udp"
// phase failing means the local socket could not even be set up, which is
// almost always a configuration problem rather than a fleet problem. The real
// signal is in the "response" phase:
//
//   - timeout: nothing came back — the port is filtered, dropped, or dead;
//   - refused: an ICMP port-unreachable came back — the host is up and there
//     is definitively no listener, which is a different and faster answer;
//   - ok: something answered, so a listener exists.
//
// What this prober deliberately cannot tell you is whether the thing that
// answered speaks the protocol you expect. That takes a real handshake, and
// it is what the protocol-specific probers (WireGuard, AmneziaWG) will add.
type udpProber struct{}

func init() { register(udpProber{}) }

// Phase names for the UDP family. They are intentionally NOT tcp/tls, so
// toResult keeps the legacy fields out of the output for these results.
const (
	phaseUDPSend     = "udp"
	phaseUDPResponse = "response"
)

// defaultUDPAttempts is how many datagrams are sent before calling a node
// silent. UDP is lossy by design, and a single dropped packet must not be
// reported as an outage.
const defaultUDPAttempts = 3

// maxUDPAttempts bounds the retry budget: past this, the per-attempt slice of
// the phase timeout gets too short to be a meaningful wait.
const maxUDPAttempts = 10

// udpParams is the per-target `params` object for proto "udp".
type udpParams struct {
	// Payload is sent literally; PayloadHex is the same thing for payloads
	// that are not printable text. At most one may be set.
	Payload    string `json:"payload,omitempty"`
	PayloadHex string `json:"payload_hex,omitempty"`

	// Attempts is the total number of datagrams sent, not the number of
	// retries: 1 means a single shot. Zero selects the default.
	Attempts int `json:"attempts,omitempty"`
}

// parseUDPParams decodes and checks the params object, returning the payload
// bytes and the attempt count alongside it.
//
// Unknown fields are rejected: a misspelled "payload_hexx" that silently
// probed with the default payload instead would be a very quiet way to
// monitor the wrong thing.
func parseUDPParams(raw json.RawMessage) (payload []byte, attempts int, err error) {
	var p udpParams
	if len(raw) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			return nil, 0, fmt.Errorf("params: %w", err)
		}
	}

	switch {
	case p.Payload != "" && p.PayloadHex != "":
		return nil, 0, errors.New(`params: set either "payload" or "payload_hex", not both`)
	case p.PayloadHex != "":
		payload, err = hex.DecodeString(p.PayloadHex)
		if err != nil {
			return nil, 0, fmt.Errorf("params: payload_hex: %w", err)
		}
	case p.Payload != "":
		payload = []byte(p.Payload)
	default:
		// A single zero byte rather than an empty datagram: some stacks and
		// middleboxes treat a zero-length UDP packet as nothing at all.
		payload = []byte{0}
	}

	attempts = p.Attempts
	switch {
	case attempts == 0:
		attempts = defaultUDPAttempts
	case attempts < 0:
		return nil, 0, fmt.Errorf("params: attempts must be positive, got %d", attempts)
	case attempts > maxUDPAttempts:
		return nil, 0, fmt.Errorf("params: attempts must be at most %d, got %d", maxUDPAttempts, attempts)
	}

	return payload, attempts, nil
}

func (udpProber) Kind() string { return "udp" }

func (udpProber) Validate(t Target) error {
	if t.Addr == "" {
		return errors.New("addr is required")
	}
	_, _, err := parseUDPParams(t.Params)
	return err
}

func (udpProber) Probe(ctx context.Context, t Target, timeout time.Duration) Outcome {
	var out Outcome

	payload, attempts, err := parseUDPParams(t.Params)
	if err != nil {
		// Unreachable when the target came through loadTargets, which
		// validates first; handled rather than ignored so a caller that
		// skipped validation gets a result instead of a panic.
		out.Phases = append(out.Phases, Phase{Name: phaseUDPSend, Err: err.Error()})
		return out
	}

	// ---------- Phase 1: socket + first datagram ----------

	ctxDial, cancelDial := context.WithTimeout(ctx, timeout)
	defer cancelDial()

	start := time.Now()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctxDial, "udp", t.Addr)
	sendPhase := Phase{Name: phaseUDPSend, Duration: time.Since(start)}
	if err != nil {
		sendPhase.Err = err.Error()
		out.Phases = append(out.Phases, sendPhase)
		return out
	}
	defer conn.Close()

	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		sendPhase.Err = err.Error()
		sendPhase.Duration = time.Since(start)
		out.Phases = append(out.Phases, sendPhase)
		return out
	}
	if _, err := conn.Write(payload); err != nil {
		sendPhase.Err = err.Error()
		sendPhase.Duration = time.Since(start)
		out.Phases = append(out.Phases, sendPhase)
		return out
	}
	sendPhase.OK = true
	sendPhase.Duration = time.Since(start)
	out.Phases = append(out.Phases, sendPhase)

	// ---------- Phase 2: wait for any answer ----------

	// The whole phase gets one timeout, split evenly across attempts, so the
	// retries fit inside the budget the operator set instead of multiplying
	// it. -timeout stays "per phase", exactly as documented.
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	slice := timeout / time.Duration(attempts)

	start = time.Now()
	respPhase := Phase{Name: phaseUDPResponse}
	buf := make([]byte, 1500) // one MTU: enough to prove an answer arrived

	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			// Resend rather than just waiting longer: the likeliest reason for
			// silence on UDP is that the datagram was dropped, and waiting
			// does not un-drop it.
			if _, err := conn.Write(payload); err != nil {
				respPhase.Err = err.Error()
				break
			}
		}

		wait := time.Now().Add(slice)
		if wait.After(deadline) {
			wait = deadline
		}
		if err := conn.SetReadDeadline(wait); err != nil {
			respPhase.Err = err.Error()
			break
		}

		_, err := conn.Read(buf)
		if err == nil {
			respPhase.OK = true
			break
		}
		respPhase.Err = err.Error()

		// A non-timeout error is a definitive answer, not a lost packet:
		// ICMP port-unreachable surfaces here as ECONNREFUSED and means there
		// is no listener. Retrying it would only delay a result we already have.
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			break
		}
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			break
		}
	}

	respPhase.Duration = time.Since(start)
	out.Phases = append(out.Phases, respPhase)
	return out
}
