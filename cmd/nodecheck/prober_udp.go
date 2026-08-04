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

	out.Phases, _ = udpExchange{
		addr:      t.Addr,
		payload:   payload,
		attempts:  attempts,
		sendPhase: phaseUDPSend,
		respPhase: phaseUDPResponse,
		// accept is nil: any datagram counts. This prober cannot tell whether
		// the thing that answered speaks any particular protocol, and it does
		// not pretend to — see the type comment.
	}.run(ctx, timeout)

	return out
}

// udpExchange is the send-and-wait half shared by every UDP-based prober: bind
// a socket, put a datagram on the wire, then wait for an answer, resending
// within the phase budget because UDP drops packets.
//
// It is factored out rather than duplicated because the retry and deadline
// rules are the subtle part, and a second prober quietly getting them slightly
// different is how two probes of the same fleet start disagreeing.
type udpExchange struct {
	addr     string
	payload  []byte
	attempts int

	// sendPhase and respPhase name the two phases in the Outcome. The names
	// differ per protocol ("response" for a bare datagram, "handshake" for
	// WireGuard) because they claim different things.
	sendPhase string
	respPhase string

	// accept decides whether a received datagram is the answer we wanted.
	// Returning an error fails the phase immediately: something answered but
	// it was not the protocol, which is a definitive result, not a lost
	// packet worth retrying. A nil accept takes any datagram.
	accept func(reply []byte) error

	// silenceOK passes the phase when the attempts ran out without an answer.
	// It is for probes that cannot expect a reply in the first place — a
	// WireGuard initiation from an unregistered peer, for instance — where
	// silence is the designed behaviour of a healthy node rather than a
	// symptom. A definitive negative (ICMP port-unreachable, a datagram that
	// accept rejected, a failed write) still fails the phase: those say
	// something silence does not.
	silenceOK bool
}

// run returns the phases it ran, in order, plus the datagram that was accepted
// (nil when none was).
func (x udpExchange) run(ctx context.Context, timeout time.Duration) ([]Phase, []byte) {
	var phases []Phase

	// ---------- Phase 1: socket + first datagram ----------

	ctxDial, cancelDial := context.WithTimeout(ctx, timeout)
	defer cancelDial()

	start := time.Now()
	var dialer net.Dialer
	// A connected socket, not ListenPacket: it is what makes the kernel
	// surface an ICMP port-unreachable as a read error, and that error is the
	// difference between "no listener" and "filtered".
	conn, err := dialer.DialContext(ctxDial, "udp", x.addr)
	sendPhase := Phase{Name: x.sendPhase, Duration: time.Since(start)}
	if err != nil {
		sendPhase.Err = err.Error()
		return append(phases, sendPhase), nil
	}
	defer conn.Close()

	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		sendPhase.Err = err.Error()
		sendPhase.Duration = time.Since(start)
		return append(phases, sendPhase), nil
	}
	if _, err := conn.Write(x.payload); err != nil {
		sendPhase.Err = err.Error()
		sendPhase.Duration = time.Since(start)
		return append(phases, sendPhase), nil
	}
	sendPhase.OK = true
	sendPhase.Duration = time.Since(start)
	phases = append(phases, sendPhase)

	// ---------- Phase 2: wait for the answer ----------

	// The whole phase gets one timeout, split evenly across attempts, so the
	// retries fit inside the budget the operator set instead of multiplying
	// it. -timeout stays "per phase", exactly as documented.
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	slice := timeout / time.Duration(x.attempts)

	start = time.Now()
	respPhase := Phase{Name: x.respPhase}
	buf := make([]byte, 1500) // one MTU: enough for any handshake message
	var reply []byte

	// definitive records that we stopped for a reason that says something in
	// its own right, as opposed to simply not being answered. It is what keeps
	// silenceOK from papering over a refused port.
	definitive := false

	for attempt := 0; attempt < x.attempts; attempt++ {
		if attempt > 0 {
			// Resend rather than just waiting longer: the likeliest reason for
			// silence on UDP is that the datagram was dropped, and waiting
			// does not un-drop it.
			if _, err := conn.Write(x.payload); err != nil {
				respPhase.Err = err.Error()
				definitive = true
				break
			}
		}

		wait := time.Now().Add(slice)
		if wait.After(deadline) {
			wait = deadline
		}
		if err := conn.SetReadDeadline(wait); err != nil {
			respPhase.Err = err.Error()
			definitive = true
			break
		}

		n, err := conn.Read(buf)
		if err == nil {
			if x.accept != nil {
				if err := x.accept(buf[:n]); err != nil {
					// Something is listening, but it is not what we asked for.
					// That is an answer, so stop asking.
					respPhase.Err = err.Error()
					definitive = true
					break
				}
			}
			reply = append([]byte(nil), buf[:n]...)
			respPhase.OK = true
			break
		}
		respPhase.Err = err.Error()

		// A non-timeout error is a definitive answer, not a lost packet:
		// ICMP port-unreachable surfaces here as ECONNREFUSED and means there
		// is no listener. Retrying it would only delay a result we already have.
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			definitive = true
			break
		}
		if ctx.Err() != nil {
			// Cancelled from the outside: we simply stopped asking, so this is
			// not a statement about the node either way.
			definitive = true
			break
		}
		if !time.Now().Before(deadline) {
			break
		}
	}

	if !respPhase.OK && x.silenceOK && !definitive {
		respPhase.OK = true
		respPhase.Err = ""
	}

	respPhase.Duration = time.Since(start)
	return append(phases, respPhase), reply
}
