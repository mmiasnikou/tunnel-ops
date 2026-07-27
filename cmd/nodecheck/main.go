// Command nodecheck concurrently probes the reachability of tunnel exit nodes.
//
// Every node is probed in two distinct phases:
//
//  1. TCP connect — is the port open at all;
//  2. TLS handshake with the expected SNI — for VLESS Reality this is the
//     masquerade site. If TCP succeeds but TLS fails, the port is listening
//     but Reality is misconfigured or the traffic is being intercepted.
//     Splitting the phases is what surfaces that signal; a single boolean
//     health check would report the node as simply "down" and lose it.
//
// Output is either JSON (for humans and scripts) or Prometheus text format,
// which can be scraped directly like any other exporter.
//
// No external dependencies — standard library only.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// version is injected by the linker at build time:
//
//	go build -ldflags="-X main.version=v1.0.0"
//
// The default "dev" means the binary was built locally, off any tag.
var version = "dev"

// Target is a single node to probe.
//
// The backtick strings after each field are struct tags. encoding/json reads
// them to map a Go field onto a key in the file: Name <-> "name".
type Target struct {
	Name   string `json:"name"`   // human-readable label, e.g. "de-fra-01"
	Addr   string `json:"addr"`   // host:port, e.g. "1.2.3.4:443"
	SNI    string `json:"sni"`    // expected masquerade host (Reality)
	Region string `json:"region"` // monitoring label: "de", "nl"
}

// Result is the outcome of one probe.
//
// The bare `Target` on the first line is struct embedding. Every field of
// Target becomes reachable as res.Name, res.Addr and so on, and in JSON they
// are emitted flat rather than as a nested object.
type Result struct {
	Target

	OK        bool    `json:"ok"`
	TCPTime   float64 `json:"tcp_seconds"`
	TLSTime   float64 `json:"tls_seconds"`
	TLSVer    string  `json:"tls_version,omitempty"` // omitempty: skip when unset
	ALPN      string  `json:"alpn,omitempty"`
	CertCN    string  `json:"cert_cn,omitempty"`
	CertMatch bool    `json:"cert_match"`
	Error     string  `json:"error,omitempty"`
}

// probe checks a single node and returns a Result. Returning a value rather
// than mutating an argument is the idiomatic Go choice.
//
// ctx allows the whole batch to be cancelled from the outside (Ctrl+C, a
// shared deadline). timeout bounds each phase separately.
func probe(ctx context.Context, t Target, timeout time.Duration) Result {
	res := Result{Target: t}

	// ---------- Phase 1: TCP ----------

	// context.WithTimeout returns TWO values: a derived context and a cancel
	// func. Go requires the cancel func to be called, so it goes in a defer
	// and runs when this function returns.
	ctxTCP, cancelTCP := context.WithTimeout(ctx, timeout)
	defer cancelTCP()

	start := time.Now()
	var dialer net.Dialer // the zero value of net.Dialer is immediately usable
	conn, err := dialer.DialContext(ctxTCP, "tcp", t.Addr)
	res.TCPTime = time.Since(start).Seconds()

	// Canonical Go: an error is an ordinary return value, checked immediately
	// after the call that produced it.
	if err != nil {
		res.Error = "tcp: " + err.Error()
		return res
	}
	conn.Close() // the TCP phase is measured; the connection is no longer needed

	// ---------- Phase 2: TLS ----------

	// If no SNI was configured, fall back to the host part of the address.
	sni := t.SNI
	if sni == "" {
		if host, _, splitErr := net.SplitHostPort(t.Addr); splitErr == nil {
			// The blank identifier _ means "this value is not needed" (the port).
			sni = host
		}
	}

	ctxTLS, cancelTLS := context.WithTimeout(ctx, timeout)
	defer cancelTLS()

	tlsDialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			ServerName: sni,
			MinVersion: tls.VersionTLS12,
			// Advertise the same ALPN a real browser would. This matters for
			// Reality: the server must answer exactly like the site it is
			// impersonating, otherwise it stands out to active probing.
			NextProtos: []string{"h2", "http/1.1"},
			// Chain verification is deliberately left ON. A Reality node is
			// supposed to present the genuine certificate of a real third-party
			// site. If it cannot, that is itself the signal, and the handshake
			// will fail on its own.
		},
	}

	start = time.Now()
	tlsConn, err := tlsDialer.DialContext(ctxTLS, "tcp", t.Addr)
	res.TLSTime = time.Since(start).Seconds()
	if err != nil {
		res.Error = "tls: " + err.Error()
		return res
	}
	defer tlsConn.Close()

	// DialContext hands back a net.Conn interface. We need the concrete
	// *tls.Conn to inspect handshake details — that is a type assertion. The
	// two-value form (v, ok) returns false instead of panicking on mismatch.
	tc, ok := tlsConn.(*tls.Conn)
	if !ok {
		res.Error = "tls: unexpected connection type"
		return res
	}

	state := tc.ConnectionState()
	res.TLSVer = tlsVersionName(state.Version)
	res.ALPN = state.NegotiatedProtocol
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		res.CertCN = leaf.Subject.CommonName
		// VerifyHostname returns an error; nil means the name matched.
		res.CertMatch = leaf.VerifyHostname(sni) == nil
	}

	res.OK = true
	return res
}

// runAll probes every target concurrently, but never more than conc at once.
func runAll(ctx context.Context, targets []Target, timeout time.Duration, conc int) []Result {
	if conc < 1 {
		conc = 1
	}

	var wg sync.WaitGroup

	// A buffered channel used as a semaphore: it holds exactly conc permits.
	// struct{}{} is the empty struct — zero bytes — the idiomatic way to say
	// "the value does not matter, only the slot does".
	sem := make(chan struct{}, conc)

	// Buffering the results channel to len(targets) guarantees a writing
	// goroutine never blocks on send.
	out := make(chan Result, len(targets))

	for _, t := range targets {
		wg.Add(1) // increment BEFORE launching, never inside the goroutine

		// go func(...) {...}(t) launches a goroutine. Since Go 1.22 the loop
		// variable is per-iteration, but passing it as a parameter is a habit
		// that stays correct on every version.
		go func(t Target) {
			defer wg.Done()          // decrement on any exit path
			sem <- struct{}{}        // take a permit (blocks when all are held)
			defer func() { <-sem }() // release it

			out <- probe(ctx, t, timeout)
		}(t)
	}

	wg.Wait() // wait for every goroutine to finish
	close(out)

	// make with a third argument: length 0, capacity len(targets) — append
	// will never have to reallocate the backing array.
	results := make([]Result, 0, len(targets))
	for r := range out { // ranging a closed channel drains it and stops
		results = append(results, r)
	}
	return results
}

func loadTargets(path string) ([]Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err // do not swallow the error, hand it to the caller
	}

	var targets []Target
	if err := json.Unmarshal(data, &targets); err != nil {
		// %w wraps the original error so it can be recovered later with
		// errors.Is / errors.As.
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("target list is empty: %s", path)
	}
	return targets, nil
}

// writeProm prints the results in Prometheus text format.
//
// Taking an io.Writer instead of hard-coding os.Stdout keeps the function
// trivially testable — a bytes.Buffer drops straight in.
func writeProm(w io.Writer, results []Result) {
	fmt.Fprintln(w, "# HELP vpnnode_up Node is reachable (both TCP and TLS succeeded)")
	fmt.Fprintln(w, "# TYPE vpnnode_up gauge")
	for _, r := range results {
		fmt.Fprintf(w, "vpnnode_up{%s} %d\n", labels(r), boolToInt(r.OK))
	}

	fmt.Fprintln(w, "# HELP vpnnode_tcp_connect_seconds Time spent on the TCP connect phase")
	fmt.Fprintln(w, "# TYPE vpnnode_tcp_connect_seconds gauge")
	for _, r := range results {
		fmt.Fprintf(w, "vpnnode_tcp_connect_seconds{%s} %.4f\n", labels(r), r.TCPTime)
	}

	fmt.Fprintln(w, "# HELP vpnnode_tls_handshake_seconds Time spent on the TLS handshake phase")
	fmt.Fprintln(w, "# TYPE vpnnode_tls_handshake_seconds gauge")
	for _, r := range results {
		fmt.Fprintf(w, "vpnnode_tls_handshake_seconds{%s} %.4f\n", labels(r), r.TLSTime)
	}

	fmt.Fprintln(w, "# HELP vpnnode_cert_match Presented certificate matches the expected SNI")
	fmt.Fprintln(w, "# TYPE vpnnode_cert_match gauge")
	for _, r := range results {
		fmt.Fprintf(w, "vpnnode_cert_match{%s} %d\n", labels(r), boolToInt(r.CertMatch))
	}
}

// labels builds the metric label set.
//
// Deliberately limited to node and region: both are BOUNDED cardinality. Do
// not add user_id, session_id or the host:port pair here — that is the direct
// route to a cardinality explosion and a dead metrics store.
func labels(r Result) string {
	return fmt.Sprintf(`node="%s",region="%s"`, escapeLabel(r.Name), escapeLabel(r.Region))
}

func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func main() {
	// flag.String returns a *string. The value is read after flag.Parse() by
	// dereferencing it: *targetsFile.
	targetsFile := flag.String("targets", "targets.json", "JSON file listing the nodes to probe")
	timeout := flag.Duration("timeout", 5*time.Second, "timeout applied to each probe phase")
	conc := flag.Int("concurrency", 32, "maximum number of probes running at once")
	format := flag.String("format", "json", "output format: json | prom")
	showVer := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVer {
		fmt.Println("nodecheck", version)
		return
	}

	targets, err := loadTargets(*targetsFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	results := runAll(context.Background(), targets, *timeout, *conc)

	// sort.Slice takes a comparison func — a closure that can see the
	// results variable from the enclosing scope.
	sort.Slice(results, func(i, j int) bool {
		return results[i].Name < results[j].Name
	})

	switch *format {
	case "prom":
		writeProm(os.Stdout, results)
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fmt.Fprintln(os.Stderr, "output error:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown format: %s\n", *format)
		os.Exit(2)
	}

	// Exit 1 if any node is down — convenient for cron jobs and alerting.
	for _, r := range results {
		if !r.OK {
			os.Exit(1)
		}
	}
}
