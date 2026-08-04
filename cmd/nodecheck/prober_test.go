package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProberForDefaultsToTLS(t *testing.T) {
	cases := []struct {
		name string
		in   Target
		want string
	}{
		{"empty proto is the original check", Target{Addr: "1.2.3.4:443"}, "tls"},
		{"explicit tls", Target{Addr: "1.2.3.4:443", Proto: "tls"}, "tls"},
		{"udp", Target{Addr: "1.2.3.4:51820", Proto: "udp"}, "udp"},
		{"wireguard", Target{Addr: "1.2.3.4:51820", Proto: "wireguard"}, "wireguard"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := proberFor(c.in)
			if err != nil {
				t.Fatalf("proberFor: %v", err)
			}
			if got := p.Kind(); got != c.want {
				t.Errorf("got prober %q, want %q", got, c.want)
			}
		})
	}
}

func TestProberForUnknownProto(t *testing.T) {
	_, err := proberFor(Target{Addr: "1.2.3.4:443", Proto: "quic"})
	if err == nil {
		t.Fatal("an unregistered proto must be rejected")
	}
	// The message should list what IS available — a typo is the likeliest cause.
	for _, kind := range []string{"tls", "udp", "wireguard"} {
		if !strings.Contains(err.Error(), kind) {
			t.Errorf("error should list %q among the known protos, got %v", kind, err)
		}
	}
}

// TestToResultKeepsLegacyFieldsForUnreachedPhases pins the exact behaviour the
// pointer conversion could have silently broken: a node that never got past
// TCP still reports tls_ok and tls_seconds, because it always did.
func TestToResultKeepsLegacyFieldsForUnreachedPhases(t *testing.T) {
	res := toResult(
		Target{Name: "down", Addr: "127.0.0.1:1"},
		Outcome{
			Phases: []Phase{{Name: phaseTCP, Duration: time.Millisecond, Err: "connection refused"}},
			TLS:    &TLSInfo{ServerName: "example.com"},
		},
	)

	if res.OK {
		t.Error("a failed TCP phase must not be reported as OK")
	}
	if res.Error != "tcp: connection refused" {
		t.Errorf("the phase prefix is part of the contract, got %q", res.Error)
	}
	for name, got := range map[string]any{
		"tcp_ok":     res.TCPOK,
		"tls_ok":     res.TLSOK,
		"cert_match": res.CertMatch,
	} {
		p, _ := got.(*bool)
		if p == nil {
			t.Errorf("%s must still be emitted for a TCP+TLS probe", name)
		} else if *p {
			t.Errorf("%s should be false", name)
		}
	}
	if res.TLSTime == nil || *res.TLSTime != 0 {
		t.Errorf("tls_seconds must be emitted as 0 for a phase never reached, got %v", res.TLSTime)
	}
	if res.Phases != nil {
		t.Error("a TCP+TLS result must not carry the generic phases array")
	}
}

func TestToResultOmitsTCPFieldsForNonTLSProbers(t *testing.T) {
	res := toResult(
		Target{Name: "wg-01", Addr: "127.0.0.1:51820", Proto: "udp"},
		Outcome{Phases: []Phase{
			{Name: phaseUDPSend, OK: true, Duration: 200 * time.Microsecond},
			{Name: phaseUDPResponse, OK: true, Duration: 18 * time.Millisecond},
		}},
	)

	if !res.OK {
		t.Fatal("both phases passed, the node is up")
	}
	// The point of the pointers: absent means "no such phase", not "it failed".
	if res.TCPOK != nil || res.TLSOK != nil || res.TCPTime != nil || res.TLSTime != nil || res.CertMatch != nil {
		t.Error("a UDP result must not claim anything about TCP, TLS or certificates")
	}
	if len(res.Phases) != 2 {
		t.Fatalf("expected both phases reported, got %d", len(res.Phases))
	}
	if res.Phases[1].Name != phaseUDPResponse || res.Phases[1].Seconds <= 0 {
		t.Errorf("unexpected response phase: %+v", res.Phases[1])
	}

	// And the JSON must be free of the legacy keys entirely.
	encoded, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"tcp_ok", "tls_ok", "tcp_seconds", "tls_seconds", "cert_match"} {
		if bytes.Contains(encoded, []byte(`"`+key+`"`)) {
			t.Errorf("UDP result should not contain %q: %s", key, encoded)
		}
	}
}

// TestResultDoesNotEchoParams keeps prober settings off the output surface.
// A Result is printed, piped into a textfile collector, logged and pasted into
// tickets; params are input configuration and belong on none of those.
func TestResultDoesNotEchoParams(t *testing.T) {
	target := Target{
		Name:   "udp-01",
		Addr:   "127.0.0.1:51820",
		Proto:  "udp",
		Params: json.RawMessage(`{"payload_hex":"deadbeef"}`),
	}

	res := toResult(target, Outcome{Phases: []Phase{
		{Name: phaseUDPSend, OK: true, Duration: time.Millisecond},
		{Name: phaseUDPResponse, OK: true, Duration: 5 * time.Millisecond},
	}})

	if res.Params != nil {
		t.Errorf("params must not travel with the result, got %s", res.Params)
	}

	encoded, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("deadbeef")) || bytes.Contains(encoded, []byte(`"params"`)) {
		t.Errorf("params leaked into the output: %s", encoded)
	}

	// Stripping the copy must not disturb the caller's target — the prober is
	// handed the original and still needs them.
	if target.Params == nil {
		t.Error("toResult must not mutate the target it was given")
	}
}

func TestToResultFirstFailingPhaseWins(t *testing.T) {
	res := toResult(Target{Name: "n"}, Outcome{Phases: []Phase{
		{Name: phaseUDPSend, Err: "network unreachable"},
		{Name: phaseUDPResponse, Err: "not reached"},
	}})

	if res.Error != "udp: network unreachable" {
		t.Errorf("the earliest failure is the diagnosis, got %q", res.Error)
	}
}

// --- targets file validation ---------------------------------------------

func writeTargets(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targets.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadTargetsRejectsBadConfigBeforeProbing(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			"unknown proto",
			`[{"name":"a","addr":"1.2.3.4:443","proto":"quic"}]`,
			"unknown proto",
		},
		{
			"missing addr",
			`[{"name":"a","proto":"udp"}]`,
			"addr is required",
		},
		{
			"misspelled param",
			`[{"name":"a","addr":"1.2.3.4:51820","proto":"udp","params":{"payloadd":"x"}}]`,
			"params",
		},
		{
			"both payload forms",
			`[{"name":"a","addr":"1.2.3.4:51820","proto":"udp","params":{"payload":"x","payload_hex":"00"}}]`,
			"not both",
		},
		{
			"odd hex payload",
			`[{"name":"a","addr":"1.2.3.4:51820","proto":"udp","params":{"payload_hex":"abc"}}]`,
			"payload_hex",
		},
		{
			"too many attempts",
			`[{"name":"a","addr":"1.2.3.4:51820","proto":"udp","params":{"attempts":99}}]`,
			"attempts",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadTargets(writeTargets(t, c.body))
			if err == nil {
				t.Fatal("expected the file to be rejected")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error should mention %q, got %v", c.want, err)
			}
			// Naming the offending target matters when the file has 200 of them.
			if !strings.Contains(err.Error(), "a") {
				t.Errorf("error should identify the target, got %v", err)
			}
		})
	}
}

func TestLoadTargetsAcceptsUDPTargets(t *testing.T) {
	path := writeTargets(t, `[
	  {"name":"wg-01","addr":"1.2.3.4:51820","region":"de","proto":"udp",
	   "params":{"payload_hex":"0100000000","attempts":2}}
	]`)

	targets, err := loadTargets(path)
	if err != nil {
		t.Fatalf("valid UDP target rejected: %v", err)
	}
	if targets[0].Proto != "udp" {
		t.Errorf("proto not parsed: %+v", targets[0])
	}
}

// --- the TLS prober -------------------------------------------------------

// TestTLSProbeReportsSNIWhenTCPFails pins why the effective SNI is resolved
// before the first phase rather than between them.
//
// A node identified by "127.0.0.1" when it answers and by "" when it does not
// is two different nodes to anything that groups results — a dashboard, an
// alert, probestore's (addr, sni) key. The identity of a node cannot depend on
// how far its probe happened to get, least of all on whether it was reachable.
func TestTLSProbeReportsSNIWhenTCPFails(t *testing.T) {
	cases := []struct {
		name   string
		target Target
		want   string
	}{
		{
			// Port 1 on localhost is almost certainly closed, so the probe
			// never reaches the point where SNI would be used.
			"derived from addr when not configured",
			Target{Name: "no-sni", Addr: "127.0.0.1:1"},
			"127.0.0.1",
		},
		{
			"configured value is kept as is",
			Target{Name: "with-sni", Addr: "127.0.0.1:1", SNI: "www.microsoft.com"},
			"www.microsoft.com",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := probe(context.Background(), c.target, 500*time.Millisecond)

			// The premise of the test: the TCP phase really did fail.
			if res.OK || !strings.HasPrefix(res.Error, phaseTCP+":") {
				t.Fatalf("expected a TCP-phase failure, got ok=%v err=%q", res.OK, res.Error)
			}
			if res.TLSOK == nil || *res.TLSOK {
				t.Fatal("the TLS phase must not have run")
			}

			if res.SNI != c.want {
				t.Errorf("SNI = %q, want %q — a node must be reported under the "+
					"name it was probed under whether or not the probe got there",
					res.SNI, c.want)
			}
		})
	}
}

// --- the UDP prober -------------------------------------------------------

// udpEcho starts a local UDP server. reply decides, per received datagram,
// whether to answer — which is how the retry behaviour gets tested.
func udpEcho(t *testing.T, reply func(n int) bool) (addr string, received func() int) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })

	count := make(chan int, 64)
	go func() {
		buf := make([]byte, 1500)
		seen := 0
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return // listener closed
			}
			seen++
			select {
			case count <- seen:
			default:
			}
			if reply(seen) {
				pc.WriteTo(buf[:n], from)
			}
		}
	}()

	return pc.LocalAddr().String(), func() int {
		last := 0
		for {
			select {
			case n := <-count:
				last = n
			default:
				return last
			}
		}
	}
}

func TestUDPProbeAnswered(t *testing.T) {
	addr, _ := udpEcho(t, func(int) bool { return true })

	res := probe(context.Background(),
		Target{Name: "udp-ok", Addr: addr, Proto: "udp"},
		2*time.Second)

	if !res.OK {
		t.Fatalf("a replying server must probe healthy, got %q", res.Error)
	}
	if len(res.Phases) != 2 || !res.Phases[0].OK || !res.Phases[1].OK {
		t.Fatalf("both phases should have passed: %+v", res.Phases)
	}
}

func TestUDPProbeSilentServer(t *testing.T) {
	// A socket that receives and never answers: the datagram left, nothing
	// came back. This is the failure mode a filtered port produces.
	addr, _ := udpEcho(t, func(int) bool { return false })

	res := probe(context.Background(),
		Target{Name: "udp-silent", Addr: addr, Proto: "udp",
			Params: json.RawMessage(`{"attempts":2}`)},
		300*time.Millisecond)

	if res.OK {
		t.Fatal("silence must not be reported as healthy")
	}
	if !strings.HasPrefix(res.Error, phaseUDPResponse+":") {
		t.Errorf("the response phase is what failed, got %q", res.Error)
	}
	if len(res.Phases) != 2 || !res.Phases[0].OK {
		t.Fatalf("the send phase should have succeeded: %+v", res.Phases)
	}
}

func TestUDPProbeRetriesLostDatagrams(t *testing.T) {
	// Ignore the first two datagrams, answer the third. UDP loses packets, and
	// a prober that gave up after one would report a healthy node as down.
	addr, received := udpEcho(t, func(n int) bool { return n >= 3 })

	res := probe(context.Background(),
		Target{Name: "udp-lossy", Addr: addr, Proto: "udp",
			Params: json.RawMessage(`{"attempts":3}`)},
		3*time.Second)

	if !res.OK {
		t.Fatalf("the third attempt was answered, expected healthy: %q", res.Error)
	}
	if got := received(); got != 3 {
		t.Errorf("expected 3 datagrams sent, server saw %d", got)
	}
}

func TestUDPProbeRespectsPhaseTimeout(t *testing.T) {
	addr, _ := udpEcho(t, func(int) bool { return false })

	const timeout = 200 * time.Millisecond
	start := time.Now()
	res := probe(context.Background(),
		Target{Name: "udp-slow", Addr: addr, Proto: "udp",
			Params: json.RawMessage(`{"attempts":4}`)},
		timeout)
	elapsed := time.Since(start)

	if res.OK {
		t.Fatal("expected a failure")
	}
	// Retries share the phase budget, they do not multiply it. Some slack for
	// scheduling, but nowhere near attempts x timeout.
	if elapsed > 2*timeout {
		t.Errorf("retries overran the phase timeout: %v for a %v budget", elapsed, timeout)
	}
}

func TestUDPProbeCustomPayload(t *testing.T) {
	var got []byte
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		got = append([]byte(nil), buf[:n]...)
		pc.WriteTo([]byte("pong"), from)
	}()

	res := probe(context.Background(),
		Target{Name: "udp-payload", Addr: pc.LocalAddr().String(), Proto: "udp",
			Params: json.RawMessage(`{"payload_hex":"deadbeef"}`)},
		2*time.Second)

	<-done
	if !res.OK {
		t.Fatalf("probe failed: %q", res.Error)
	}
	if want := []byte{0xde, 0xad, 0xbe, 0xef}; !bytes.Equal(got, want) {
		t.Errorf("server received % x, want % x", got, want)
	}
}

// --- rendering rules for mixed fleets ------------------------------------

func TestWritePromSkipsPhasesThatDidNotRun(t *testing.T) {
	var buf bytes.Buffer
	writeProm(&buf, []Result{
		toResult(Target{Name: "tls-1", Region: "de"}, Outcome{
			Phases: []Phase{
				{Name: phaseTCP, OK: true, Duration: 10 * time.Millisecond},
				{Name: phaseTLS, OK: true, Duration: 20 * time.Millisecond},
			},
			TLS: &TLSInfo{CertMatch: true},
		}),
		toResult(Target{Name: "udp-1", Region: "nl", Proto: "udp"}, Outcome{
			Phases: []Phase{
				{Name: phaseUDPSend, OK: true, Duration: time.Millisecond},
				{Name: phaseUDPResponse, OK: true, Duration: 5 * time.Millisecond},
			},
		}),
	})
	out := buf.String()

	// vpnnode_up is protocol-agnostic: every node appears in it.
	for _, want := range []string{
		`vpnnode_up{node="tls-1",region="de"} 1`,
		`vpnnode_up{node="udp-1",region="nl"} 1`,
		`vpnnode_tcp_connect_seconds{node="tls-1",region="de"} 0.0100`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n---\n%s", want, out)
		}
	}

	// The phase metrics must not invent a value for a node that has no such phase.
	for _, unwanted := range []string{
		`vpnnode_tcp_connect_seconds{node="udp-1"`,
		`vpnnode_tls_handshake_seconds{node="udp-1"`,
		`vpnnode_cert_match{node="udp-1"`,
	} {
		if strings.Contains(out, unwanted) {
			t.Errorf("UDP node must not appear in a TCP/TLS series: %q\n---\n%s", unwanted, out)
		}
	}

	// The families themselves stay declared, so the scrape shape is stable.
	if !strings.Contains(out, "# TYPE vpnnode_cert_match gauge") {
		t.Error("metric families should always be declared")
	}
}
