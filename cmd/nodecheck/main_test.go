package main

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// A test function MUST be named Test... and take *testing.T — that is how
// `go test` discovers it.
func TestEscapeLabel(t *testing.T) {
	// Table-driven tests are the dominant style in Go.
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain string", `de-fra-01`, `de-fra-01`},
		{"double quote", `no"de`, `no\"de`},
		{"backslash", `no\de`, `no\\de`},
		{"newline", "no\nde", `no\nde`},
	}

	for _, c := range cases {
		// t.Run creates a subtest, so the output names exactly which case failed.
		t.Run(c.name, func(t *testing.T) {
			if got := escapeLabel(c.in); got != c.want {
				t.Errorf("escapeLabel(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestProbeDeadPort(t *testing.T) {
	// Port 1 on localhost is almost certainly closed -> connection refused.
	res := probe(context.Background(),
		Target{Name: "dead", Addr: "127.0.0.1:1"},
		500*time.Millisecond)

	if res.OK {
		t.Fatal("expected failure against a closed port")
	}
	if !strings.HasPrefix(res.Error, "tcp:") {
		t.Fatalf("expected a TCP-phase error, got %q", res.Error)
	}
}

func TestProbeTCPOkTLSFails(t *testing.T) {
	// Stand up a bare TCP listener: the TCP phase passes, the TLS phase fails.
	// This is precisely the diagnostic signal the phase split exists for.
	ln, err := net.Listen("tcp", "127.0.0.1:0") // :0 asks the OS for a free port
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Accept loop in a goroutine: accept and immediately close.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return // listener closed — leave
			}
			c.Close()
		}
	}()

	res := probe(context.Background(),
		Target{Name: "local", Addr: ln.Addr().String(), SNI: "example.com"},
		2*time.Second)

	if res.OK {
		t.Fatal("a bare TCP listener must not pass the TLS phase")
	}
	if !strings.HasPrefix(res.Error, "tls:") {
		t.Fatalf("expected a TLS-phase error, got %q", res.Error)
	}
	if res.TCPTime <= 0 {
		t.Error("the TCP phase duration should have been measured")
	}
}

func TestRunAllConcurrency(t *testing.T) {
	targets := []Target{
		{Name: "a", Addr: "127.0.0.1:1"},
		{Name: "b", Addr: "127.0.0.1:1"},
		{Name: "c", Addr: "127.0.0.1:1"},
	}

	results := runAll(context.Background(), targets, 300*time.Millisecond, 2)

	if len(results) != len(targets) {
		t.Fatalf("got %d results, want %d", len(results), len(targets))
	}
}

func TestWritePromFormat(t *testing.T) {
	// bytes.Buffer implements io.Writer — it substitutes for os.Stdout.
	var buf bytes.Buffer
	writeProm(&buf, []Result{
		{Target: Target{Name: "de-1", Region: "de"}, OK: true, TCPTime: 0.031},
	})

	out := buf.String()
	for _, want := range []string{
		"# TYPE vpnnode_up gauge",
		`vpnnode_up{node="de-1",region="de"} 1`,
		"vpnnode_tcp_connect_seconds",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q\n---\n%s", want, out)
		}
	}
}
