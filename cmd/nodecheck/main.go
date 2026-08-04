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
	"net/http"
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

	// Provider is the hosting vendor ("hetzner", "vultr"). Optional, and
	// deliberately separate from Region: when a provider starts getting its
	// ranges filtered, the failures cluster by vendor, not by geography.
	Provider string `json:"provider,omitempty"`

	// Proto selects the prober (see prober.go). Empty means "tls", the
	// original TCP+TLS check, so every targets file written before probers
	// existed keeps working untouched.
	Proto string `json:"proto,omitempty"`

	// Params holds prober-specific settings, left as raw JSON so each prober
	// decodes its own shape. Keeping them here instead of adding a field per
	// protocol is what stops Target from growing a column for every future
	// check.
	//
	// Secrets do not belong here — same reason the push token is env-only:
	// a targets file gets copied around, committed and pasted into tickets.
	Params json.RawMessage `json:"params,omitempty"`
}

// Result is the outcome of one probe.
//
// The bare `Target` on the first line is struct embedding. Every field of
// Target becomes reachable as res.Name, res.Addr and so on, and in JSON they
// are emitted flat rather than as a nested object.
type Result struct {
	Target

	OK bool `json:"ok"`

	// TCPOK and TLSOK record which phases actually succeeded. Without them a
	// consumer has to guess by string-matching the Error prefix, which breaks
	// the moment the wording changes.
	//
	// They are pointers because not every prober has these phases at all. For
	// a TCP+TLS probe they are always emitted — including as false for a
	// phase that was never reached, exactly as before probers existed. For a
	// UDP probe the keys are absent, which says "not applicable"; emitting
	// false there would claim a TCP connect was tried and failed.
	TCPOK *bool `json:"tcp_ok,omitempty"`
	TLSOK *bool `json:"tls_ok,omitempty"`

	// Timestamp is when the probe finished, in UTC. Set by the caller so
	// there is exactly one place doing it.
	Timestamp time.Time `json:"ts"`

	TCPTime   *float64 `json:"tcp_seconds,omitempty"`
	TLSTime   *float64 `json:"tls_seconds,omitempty"`
	TLSVer    string   `json:"tls_version,omitempty"` // omitempty: skip when unset
	ALPN      string   `json:"alpn,omitempty"`
	CertCN    string   `json:"cert_cn,omitempty"`
	CertMatch *bool    `json:"cert_match,omitempty"`
	Error     string   `json:"error,omitempty"`

	// Phases reports the raw phase list for probers whose phases the tcp_*
	// and tls_* fields above cannot express. Absent for TCP+TLS results, so
	// the historical output is unchanged byte for byte.
	Phases []phaseJSON `json:"phases,omitempty"`
}

// phaseJSON is the wire form of Phase.
//
// Separate from the domain type for the same reason push.go keeps its own
// payload types: Phase measures a time.Duration, while the output has always
// reported seconds as a float, and neither side should have to bend to the
// other.
type phaseJSON struct {
	Name    string  `json:"name"`
	OK      bool    `json:"ok"`
	Seconds float64 `json:"seconds"`
	Error   string  `json:"error,omitempty"`
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

			r := probe(ctx, t, timeout)
			r.Timestamp = time.Now().UTC()
			out <- r
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

	// Resolve and validate every prober up front. A target naming a protocol
	// that does not exist, or missing a parameter its protocol needs, is a
	// broken config — and reporting it as a node that failed its probe would
	// hide a typo inside what looks like an outage. Failing here also means
	// nothing is pushed, so probestore never records a fake down node.
	for i, t := range targets {
		p, err := proberFor(t)
		if err != nil {
			return nil, fmt.Errorf("%s: target %d (%s): %w", path, i, t.Name, err)
		}
		if err := p.Validate(t); err != nil {
			return nil, fmt.Errorf("%s: target %d (%s): %s: %w", path, i, t.Name, p.Kind(), err)
		}
	}

	return targets, nil
}

// writeProm prints the results in Prometheus text format.
//
// Taking an io.Writer instead of hard-coding os.Stdout keeps the function
// trivially testable — a bytes.Buffer drops straight in.
//
// vpnnode_up is emitted for every result, because "is this node reachable" is
// the one question that means the same thing whatever the protocol. The phase
// metrics are emitted only for the results that actually ran that phase: a
// UDP node has no TLS handshake, and publishing 0.0000 for it would put an
// invented value into a series that dashboards average. A gap is the honest
// encoding of "not measured", and Prometheus already handles gaps.
//
// The HELP/TYPE lines are printed unconditionally so the exporter declares the
// same set of metric families on every scrape, even for a fleet where nothing
// currently populates one of them.
func writeProm(w io.Writer, results []Result) {
	fmt.Fprintln(w, "# HELP vpnnode_up Node is reachable (both TCP and TLS succeeded)")
	fmt.Fprintln(w, "# TYPE vpnnode_up gauge")
	for _, r := range results {
		fmt.Fprintf(w, "vpnnode_up{%s} %d\n", labels(r), boolToInt(r.OK))
	}

	fmt.Fprintln(w, "# HELP vpnnode_tcp_connect_seconds Time spent on the TCP connect phase")
	fmt.Fprintln(w, "# TYPE vpnnode_tcp_connect_seconds gauge")
	for _, r := range results {
		if r.TCPTime != nil {
			fmt.Fprintf(w, "vpnnode_tcp_connect_seconds{%s} %.4f\n", labels(r), *r.TCPTime)
		}
	}

	fmt.Fprintln(w, "# HELP vpnnode_tls_handshake_seconds Time spent on the TLS handshake phase")
	fmt.Fprintln(w, "# TYPE vpnnode_tls_handshake_seconds gauge")
	for _, r := range results {
		if r.TLSTime != nil {
			fmt.Fprintf(w, "vpnnode_tls_handshake_seconds{%s} %.4f\n", labels(r), *r.TLSTime)
		}
	}

	fmt.Fprintln(w, "# HELP vpnnode_cert_match Presented certificate matches the expected SNI")
	fmt.Fprintln(w, "# TYPE vpnnode_cert_match gauge")
	for _, r := range results {
		if r.CertMatch != nil {
			fmt.Fprintf(w, "vpnnode_cert_match{%s} %d\n", labels(r), boolToInt(*r.CertMatch))
		}
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
	pushURL := flag.String("push-url", "", "probestore ingest endpoint, e.g. https://probes.example.com/v1/runs")
	pushTimeout := flag.Duration("push-timeout", 10*time.Second, "timeout for the push request")
	pushSource := flag.String("push-source", "", "source label recorded with the run (default: nodecheck@<hostname>)")
	flag.Parse()

	// The bearer token comes from the environment, never from a flag:
	// command-line arguments are world-readable in /proc, so any local user
	// could lift it out of ps.
	pushToken := os.Getenv("NODECHECK_PUSH_TOKEN")

	if *showVer {
		fmt.Println("nodecheck", version)
		return
	}

	targets, err := loadTargets(*targetsFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	startedAt := time.Now().UTC()
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

	if *pushURL != "" {
		source := *pushSource
		if source == "" {
			host, err := os.Hostname()
			if err != nil || host == "" {
				host = "unknown"
			}
			source = "nodecheck@" + host
		}

		runID, err := newUUIDv4()
		if err != nil {
			fmt.Fprintln(os.Stderr, "push error:", err)
			os.Exit(3)
		}

		ctx, cancel := context.WithTimeout(context.Background(), *pushTimeout)
		client := &http.Client{Timeout: *pushTimeout}
		err = pushResults(ctx, client, *pushURL, pushToken, buildPayload(runID, source, startedAt, results))
		cancel()

		if err != nil {
			// Exit 3 keeps this distinct from "a node is down": the nodes may
			// be perfectly healthy while the prober itself failed to report,
			// and those two want different alerts.
			fmt.Fprintln(os.Stderr, "push error:", err)
			os.Exit(3)
		}
	}

	// Exit 1 if any node is down — convenient for cron jobs and alerting.
	for _, r := range results {
		if !r.OK {
			os.Exit(1)
		}
	}
}
