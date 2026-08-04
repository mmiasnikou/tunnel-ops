package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"
)

// tlsProber is the original nodecheck probe: TCP connect, then a TLS handshake
// with the expected SNI. It is the default, used by any target that does not
// name a proto.
//
// The logic below is the pre-abstraction probe() unchanged — only the shape of
// what it returns is different. Notes that explain *why* it probes this way
// have been kept with the code they describe.
type tlsProber struct{}

func init() { register(tlsProber{}) }

func (tlsProber) Kind() string { return "tls" }

func (tlsProber) Validate(t Target) error {
	if t.Addr == "" {
		return errors.New("addr is required")
	}
	// An address with no port, or an unresolvable host, is deliberately NOT
	// rejected here — the probe reports those far more precisely, and one
	// typo should not suppress the results for the rest of the fleet.
	return nil
}

func (tlsProber) Probe(ctx context.Context, t Target, timeout time.Duration) Outcome {
	var out Outcome

	// Resolve the effective SNI before probing anything. Doing it here rather
	// than between the phases means a node that fails at TCP is still
	// reported with the name it would have been probed under — otherwise the
	// same node shows up under two different identities depending on how far
	// the probe got.
	sni := t.SNI
	if sni == "" {
		if host, _, splitErr := net.SplitHostPort(t.Addr); splitErr == nil {
			// The blank identifier _ means "this value is not needed" (the port).
			sni = host
		}
	}
	info := &TLSInfo{ServerName: sni}
	out.TLS = info

	// ---------- Phase 1: TCP ----------

	// context.WithTimeout returns TWO values: a derived context and a cancel
	// func. Go requires the cancel func to be called, so it goes in a defer
	// and runs when this function returns.
	ctxTCP, cancelTCP := context.WithTimeout(ctx, timeout)
	defer cancelTCP()

	start := time.Now()
	var dialer net.Dialer // the zero value of net.Dialer is immediately usable
	conn, err := dialer.DialContext(ctxTCP, "tcp", t.Addr)
	tcpPhase := Phase{Name: phaseTCP, Duration: time.Since(start)}

	// Canonical Go: an error is an ordinary return value, checked immediately
	// after the call that produced it.
	if err != nil {
		tcpPhase.Err = err.Error()
		out.Phases = append(out.Phases, tcpPhase)
		return out
	}
	conn.Close() // the TCP phase is measured; the connection is no longer needed
	tcpPhase.OK = true
	out.Phases = append(out.Phases, tcpPhase)

	// ---------- Phase 2: TLS ----------

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
	tlsPhase := Phase{Name: phaseTLS, Duration: time.Since(start)}
	if err != nil {
		tlsPhase.Err = err.Error()
		out.Phases = append(out.Phases, tlsPhase)
		return out
	}
	defer tlsConn.Close()

	// DialContext hands back a net.Conn interface. We need the concrete
	// *tls.Conn to inspect handshake details — that is a type assertion. The
	// two-value form (v, ok) returns false instead of panicking on mismatch.
	tc, ok := tlsConn.(*tls.Conn)
	if !ok {
		tlsPhase.Err = "unexpected connection type"
		out.Phases = append(out.Phases, tlsPhase)
		return out
	}

	state := tc.ConnectionState()
	info.Version = tlsVersionName(state.Version)
	info.ALPN = state.NegotiatedProtocol
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		info.CertCN = leaf.Subject.CommonName
		// VerifyHostname returns an error; nil means the name matched.
		info.CertMatch = leaf.VerifyHostname(sni) == nil
	}

	tlsPhase.OK = true
	out.Phases = append(out.Phases, tlsPhase)
	return out
}
