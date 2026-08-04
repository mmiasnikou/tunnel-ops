package main

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// This file holds the probe abstraction: what a probe is made of (Phase,
// Outcome), who can run one (Prober), how a target picks its prober (the
// registry), and how an Outcome is projected back onto Result (toResult).
//
// The two-phase split that nodecheck was built around is not abandoned here,
// it is generalised. Every protocol has a reachability phase ("did anything
// answer at all") and a confirmation phase ("was the answer really the
// protocol we expect"). For TCP+TLS those are "tcp" and "tls". Collapsing
// them into one boolean would erase the same signal it always did.
//
// Result, by contrast, is a wire format — stdout JSON, and the source the
// Prometheus text is rendered from. Probers must not know about it. Every
// backwards-compatibility concern lives in toResult and nowhere else.

// Phase names understood by toResult. A prober using these fills the original
// tcp_*/tls_* fields of Result; any other name is reported only in `phases`.
const (
	phaseTCP = "tcp"
	phaseTLS = "tls"
)

// defaultProto is the prober used by a target that does not name one, which
// keeps every targets.json written before this abstraction existed working
// exactly as it did.
const defaultProto = "tls"

// Phase is one step of a probe.
//
// Err is set only when OK is false; Duration is measured whether the phase
// succeeded or not, because how long a failure took is itself diagnostic (a
// refusal in 1ms and a timeout at 5s are different outages).
type Phase struct {
	Name     string
	OK       bool
	Duration time.Duration
	Err      string
}

// TLSInfo carries the handshake details only a TLS-speaking prober can
// produce. A pointer on Outcome, so "no TLS here" is representable.
type TLSInfo struct {
	// ServerName is the SNI the probe actually used, which may have been
	// derived from the address rather than configured. It is reported back so
	// a node is identified by the name it was probed under, whether or not
	// the handshake got far enough to say anything else.
	ServerName string

	Version   string
	ALPN      string
	CertCN    string
	CertMatch bool
}

// Outcome is what a Prober returns: the phases it ran, in order, plus any
// protocol-specific extras.
//
// Probing stops at the first failing phase, so a short Phases slice is normal
// and means the later phases were never reached — not that they passed.
type Outcome struct {
	Phases []Phase
	TLS    *TLSInfo

	// NoLivenessClaim marks an outcome whose phases passing does not mean the
	// node is up — an anonymous WireGuard initiation, where silence is the
	// designed answer from a healthy node and therefore from an absent one
	// too. Such a result is kept out of vpnnode_up entirely: publishing a 1
	// there would be a false statement in the metric operators alert on, and
	// that is worse than having no data. The prober decides this, not the
	// renderer, because only the prober knows what its phases mean.
	//
	// The zero value claims liveness, so an ordinary prober need not think
	// about it.
	NoLivenessClaim bool
}

// failed returns the first failing phase, or nil when every phase passed.
func (o Outcome) failed() *Phase {
	for i := range o.Phases {
		if !o.Phases[i].OK {
			return &o.Phases[i]
		}
	}
	return nil
}

// Prober probes one target with one protocol.
type Prober interface {
	// Kind is the Target.Proto value that selects this prober.
	Kind() string

	// Validate rejects a target this prober could never probe — an unusable
	// address, missing or malformed params. It runs at load time, before any
	// probing starts, so a typo in the config is reported as a bad targets
	// file instead of masquerading as a fleet-wide outage.
	//
	// It deliberately does NOT pre-flight things the probe itself reports
	// better (an address with no port, an unresolvable host): those are real
	// probe failures, and rejecting the whole file for one of them would
	// throw away the results of every other node in it.
	Validate(t Target) error

	// Probe runs the phases and returns them in order. It reports transport
	// failures inside the Outcome rather than as an error return: a node
	// being down is the expected outcome of a probe, not an exception.
	Probe(ctx context.Context, t Target, timeout time.Duration) Outcome
}

// probers is the registry, keyed by Kind. Each prober file registers itself
// from init(), so adding a protocol means adding one file — the same "the
// directory listing is the config" habit the Makefile uses for cmd/*.
var probers = map[string]Prober{}

func register(p Prober) {
	if _, dup := probers[p.Kind()]; dup {
		// A duplicate kind is a programming error caught at startup, not a
		// runtime condition worth threading an error through init for.
		panic("nodecheck: duplicate prober kind " + p.Kind())
	}
	probers[p.Kind()] = p
}

// proberKinds lists the registered kinds, sorted, for error messages.
func proberKinds() []string {
	kinds := make([]string, 0, len(probers))
	for k := range probers {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return kinds
}

// proberFor resolves the prober a target asks for.
func proberFor(t Target) (Prober, error) {
	kind := t.Proto
	if kind == "" {
		kind = defaultProto
	}
	p, ok := probers[kind]
	if !ok {
		return nil, fmt.Errorf("unknown proto %q (known: %v)", kind, proberKinds())
	}
	return p, nil
}

// probe resolves the prober for one target, runs it, and projects the outcome
// onto Result. runAll calls exactly this for every target.
func probe(ctx context.Context, t Target, timeout time.Duration) Result {
	p, err := proberFor(t)
	if err != nil {
		// loadTargets rejects unknown protos before probing starts, so this is
		// unreachable in normal operation. Reporting it as a failed result
		// rather than panicking keeps a future caller that skipped validation
		// from taking the whole run down.
		r := newResult(t)
		r.Error = "config: " + err.Error()
		return r
	}
	return toResult(t, p.Probe(ctx, t, timeout))
}

// newResult starts a Result from the target it describes.
//
// Params are stripped: they are input configuration, and a Result is an
// artifact that gets printed, piped into a textfile collector, logged and
// pasted into tickets. Echoing a prober's settings back out puts them on every
// one of those surfaces for no diagnostic gain — the same reasoning that keeps
// the push token out of argv. The prober already has the params it needs; it
// is handed the original Target, not this copy.
func newResult(t Target) Result {
	t.Params = nil
	return Result{Target: t}
}

// toResult projects an Outcome onto the output struct.
//
// This is the single place that knows about the historical JSON and Prometheus
// shape, and the only reason the legacy fields are pointers: a UDP node has no
// TCP connect phase, and reporting tcp_ok=false for it would be a claim about
// a phase that was never run. Omitting the key says "not applicable"; false
// says "it was tried and it failed". Those are different facts.
//
// For a prober that does use the tcp/tls phases the legacy fields are always
// emitted, including as zeroes for a phase that was never reached — that is
// what the tool did before this abstraction existed, and dashboards built on
// it must not see a field disappear.
func toResult(t Target, o Outcome) Result {
	res := newResult(t)
	res.noLivenessClaim = o.NoLivenessClaim

	if usesLegacyPhases(o) {
		res.TCPOK = ptr(false)
		res.TLSOK = ptr(false)
		res.CertMatch = ptr(false)
		res.TCPTime = ptr(0.0)
		res.TLSTime = ptr(0.0)
	} else {
		// Anything that is not the tcp+tls family reports its phases in full,
		// since the legacy fields cannot express them.
		res.Phases = make([]phaseJSON, 0, len(o.Phases))
		for _, ph := range o.Phases {
			res.Phases = append(res.Phases, phaseJSON{
				Name:    ph.Name,
				OK:      ph.OK,
				Seconds: ph.Duration.Seconds(),
				Error:   ph.Err,
			})
		}
	}

	for _, ph := range o.Phases {
		switch ph.Name {
		case phaseTCP:
			*res.TCPOK = ph.OK
			*res.TCPTime = ph.Duration.Seconds()
		case phaseTLS:
			*res.TLSOK = ph.OK
			*res.TLSTime = ph.Duration.Seconds()
		}
	}

	if o.TLS != nil {
		if o.TLS.ServerName != "" {
			res.SNI = o.TLS.ServerName
		}
		res.TLSVer = o.TLS.Version
		res.ALPN = o.TLS.ALPN
		res.CertCN = o.TLS.CertCN
		if res.CertMatch != nil {
			*res.CertMatch = o.TLS.CertMatch
		}
	}

	// The error carries its phase as a prefix ("tcp: ...", "tls: ..."). That
	// prefix is load-bearing: consumers grep for it, and it is what tells a
	// reader which half of the probe broke.
	if bad := o.failed(); bad != nil {
		res.Error = bad.Name + ": " + bad.Err
	} else {
		res.OK = len(o.Phases) > 0
	}

	return res
}

// ptr returns a pointer to v. The output struct uses pointers to distinguish
// "measured, and the answer is zero/false" from "this probe has no such
// phase", and that distinction needs a one-liner to stay readable.
func ptr[T any](v T) *T { return &v }

// usesLegacyPhases reports whether an outcome belongs to the tcp+tls family,
// deciding it from the phase names rather than from the prober's kind so the
// projection stays a pure function of the Outcome.
func usesLegacyPhases(o Outcome) bool {
	for _, ph := range o.Phases {
		if ph.Name == phaseTCP || ph.Name == phaseTLS {
			return true
		}
	}
	return false
}
