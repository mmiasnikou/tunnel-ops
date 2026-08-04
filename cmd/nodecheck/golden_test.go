package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// The golden files in testdata/ were captured from the code as it stood BEFORE
// the Prober abstraction existed, by rendering a fixed set of results through
// the then-current Result struct and writeProm. They are the record of what
// nodecheck's two output formats looked like, and the point of this test is
// that the record still holds byte for byte.
//
// There is deliberately no -update flag. Regenerating these files is not a
// routine action: every byte in them is a contract with a dashboard, an alert
// rule or a script somebody already wrote. If a change here fails, the answer
// is almost always to change the code back, not the fixture.
//
// The fixture is rendered rather than probed because a live probe cannot be
// byte-identical twice — durations and timestamps move. What is being frozen
// is the encoding, which is exactly the part the pointer conversion put at
// risk.

// legacyOutcomes mirrors what tlsProber would have returned for the three
// targets in testdata/targets_legacy.json: one healthy, one where TCP is up
// but the handshake fails, and one refused at TCP.
//
// The third is the load-bearing case. It never reached the TLS phase, and the
// pre-abstraction code still emitted "tls_seconds": 0 for it. Now that the
// field is a pointer, the naive projection would drop the key entirely — a
// silent schema change for every failing node in the fleet.
func legacyOutcomes() []Outcome {
	return []Outcome{
		{
			Phases: []Phase{
				{Name: phaseTCP, OK: true, Duration: 31 * time.Millisecond},
				{Name: phaseTLS, OK: true, Duration: 82 * time.Millisecond},
			},
			TLS: &TLSInfo{
				ServerName: "www.microsoft.com",
				Version:    "1.3",
				ALPN:       "h2",
				CertCN:     "www.microsoft.com",
				CertMatch:  true,
			},
		},
		{
			Phases: []Phase{
				{Name: phaseTCP, OK: true, Duration: 24 * time.Millisecond},
				{Name: phaseTLS, Duration: 191 * time.Millisecond, Err: "remote error: tls: handshake failure"},
			},
			TLS: &TLSInfo{ServerName: "www.cloudflare.com"},
		},
		{
			Phases: []Phase{
				{Name: phaseTCP, Duration: 1 * time.Millisecond, Err: "dial tcp 127.0.0.1:1: connect: connection refused"},
			},
			TLS: &TLSInfo{ServerName: "example.com"},
		},
	}
}

// legacyResults loads the pre-Prober targets file — no proto anywhere — and
// projects the fixed outcomes through the real toResult.
func legacyResults(t *testing.T) []Result {
	t.Helper()

	targets, err := loadTargets("testdata/targets_legacy.json")
	if err != nil {
		t.Fatalf("a targets file with no proto field must still load: %v", err)
	}

	outcomes := legacyOutcomes()
	if len(targets) != len(outcomes) {
		t.Fatalf("fixture mismatch: %d targets, %d outcomes", len(targets), len(outcomes))
	}

	ts := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	results := make([]Result, 0, len(targets))
	for i, target := range targets {
		r := toResult(target, outcomes[i])
		r.Timestamp = ts // runAll stamps this; here it must be reproducible
		results = append(results, r)
	}
	return results
}

func TestGoldenJSONUnchanged(t *testing.T) {
	var buf bytes.Buffer
	// Encoded exactly as main() does it, indentation included.
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(legacyResults(t)); err != nil {
		t.Fatal(err)
	}

	assertGolden(t, "testdata/golden.json", buf.Bytes())
}

func TestGoldenPromUnchanged(t *testing.T) {
	var buf bytes.Buffer
	writeProm(&buf, legacyResults(t))

	assertGolden(t, "testdata/golden.prom", buf.Bytes())
}

func assertGolden(t *testing.T, path string, got []byte) {
	t.Helper()

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden file: %v", err)
	}
	if bytes.Equal(got, want) {
		return
	}

	t.Errorf("output no longer matches %s byte for byte.\n"+
		"This format is a contract with existing dashboards and scripts.\n"+
		"--- want ---\n%s\n--- got ---\n%s", path, want, got)
}
