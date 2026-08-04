package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

// Field offsets in a handshake initiation, for the tests that read one apart.
const (
	wgOffSender      = 4
	wgOffEphemeral   = 8
	wgOffEncStatic   = 40
	wgOffEncTime     = 88
	wgOffMAC1        = 116
	wgOffMAC2        = 132
	wgEncStaticSize  = 48
	wgEncTimeSize    = 28
	wgTimestampBytes = 12
)

func wgKeypair(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func wgTargetParams(t *testing.T, peer *ecdh.PublicKey, attempts int) json.RawMessage {
	t.Helper()
	p := map[string]any{"public_key": base64.StdEncoding.EncodeToString(peer.Bytes())}
	if attempts > 0 {
		p["attempts"] = attempts
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// --- the responder side, implemented independently -------------------------
//
// These helpers re-derive the Noise chain from the whitepaper using the raw
// primitives rather than the prober's own wgHash/wgKDF2/wgSeal. That is the
// point: if the prober's KDF or hash ordering were wrong, sharing its helpers
// here would cancel the error out and the test would pass anyway.

func wgTestHash(parts ...[]byte) []byte {
	h, err := blake2s.New256(nil)
	if err != nil {
		panic(err)
	}
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func wgTestHMAC(key, data []byte) []byte {
	m := hmac.New(func() hash.Hash {
		h, err := blake2s.New256(nil)
		if err != nil {
			panic(err)
		}
		return h
	}, key)
	m.Write(data)
	return m.Sum(nil)
}

func wgTestKDF(ck, input []byte, n int) [][]byte {
	temp := wgTestHMAC(ck, input)
	out := make([][]byte, 0, n)
	prev := []byte{}
	for i := 1; i <= n; i++ {
		out = append(out, wgTestHMAC(temp, append(append([]byte{}, prev...), byte(i))))
		prev = out[len(out)-1]
	}
	return out
}

func wgTestOpen(t *testing.T, key, ciphertext, aad []byte) ([]byte, error) {
	t.Helper()
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [chacha20poly1305.NonceSize]byte
	return aead.Open(nil, nonce[:], ciphertext, aad)
}

// consumeInitiation performs the responder's half of the handshake and returns
// the initiator's static public key and TAI64N timestamp. It succeeding at all
// is the proof that the initiation was assembled correctly — both AEAD tags
// only verify if every hash, KDF and DH along the way matched.
func consumeInitiation(t *testing.T, responder *ecdh.PrivateKey, packet []byte) (staticPub, timestamp []byte) {
	t.Helper()

	if len(packet) != wgInitiationSize {
		t.Fatalf("initiation is %d bytes, want %d", len(packet), wgInitiationSize)
	}
	if packet[0] != wgMsgInitiation {
		t.Fatalf("message type is %d, want %d", packet[0], wgMsgInitiation)
	}
	if !bytes.Equal(packet[1:4], []byte{0, 0, 0}) {
		t.Errorf("reserved bytes are not zero: % x", packet[1:4])
	}

	responderPub := responder.PublicKey().Bytes()

	ck := wgTestHash([]byte(wgConstruction))
	h := wgTestHash(wgTestHash(ck, []byte(wgIdentifier)), responderPub)

	ephemeral := packet[wgOffEphemeral : wgOffEphemeral+wgKeySize]
	h = wgTestHash(h, ephemeral)
	ck = wgTestKDF(ck, ephemeral, 1)[0]

	ephPub, err := ecdh.X25519().NewPublicKey(ephemeral)
	if err != nil {
		t.Fatalf("ephemeral public key is invalid: %v", err)
	}
	dh, err := responder.ECDH(ephPub)
	if err != nil {
		t.Fatal(err)
	}
	keys := wgTestKDF(ck, dh, 2)
	ck = keys[0]

	encStatic := packet[wgOffEncStatic : wgOffEncStatic+wgEncStaticSize]
	staticPub, err = wgTestOpen(t, keys[1], encStatic, h)
	if err != nil {
		t.Fatalf("encrypted_static did not decrypt — the handshake chain is wrong: %v", err)
	}
	h = wgTestHash(h, encStatic)

	initiatorStatic, err := ecdh.X25519().NewPublicKey(staticPub)
	if err != nil {
		t.Fatalf("decrypted static key is invalid: %v", err)
	}
	dh, err = responder.ECDH(initiatorStatic)
	if err != nil {
		t.Fatal(err)
	}
	keys = wgTestKDF(ck, dh, 2)

	encTime := packet[wgOffEncTime : wgOffEncTime+wgEncTimeSize]
	timestamp, err = wgTestOpen(t, keys[1], encTime, h)
	if err != nil {
		t.Fatalf("encrypted_timestamp did not decrypt — the handshake chain is wrong: %v", err)
	}

	return staticPub, timestamp
}

// --- message construction --------------------------------------------------

func TestWGInitiationIsCryptographicallyValid(t *testing.T) {
	responder := wgKeypair(t)
	initiator := wgKeypair(t)
	now := time.Date(2026, 8, 4, 12, 0, 0, 500, time.UTC)

	msg, err := buildWGInitiation(responder.PublicKey(), initiator, now)
	if err != nil {
		t.Fatalf("building the initiation: %v", err)
	}

	staticPub, timestamp := consumeInitiation(t, responder, msg.packet)

	if !bytes.Equal(staticPub, initiator.PublicKey().Bytes()) {
		t.Error("the responder decrypted a different static key than we sent")
	}
	if len(timestamp) != wgTimestampBytes {
		t.Fatalf("timestamp is %d bytes, want %d", len(timestamp), wgTimestampBytes)
	}
	// TAI64N: seconds since the TAI epoch, which is Unix time plus the epoch
	// offset. A wrong constant here would be invisible until a real responder
	// rejected the handshake as a replay.
	if got := binary.BigEndian.Uint64(timestamp[0:8]) - 0x400000000000000a; got != uint64(now.Unix()) {
		t.Errorf("timestamp decodes to unix %d, want %d", got, now.Unix())
	}
	if got := binary.BigEndian.Uint32(timestamp[8:12]); got != uint32(now.Nanosecond()) {
		t.Errorf("timestamp nanoseconds = %d, want %d", got, now.Nanosecond())
	}

	if got := binary.LittleEndian.Uint32(msg.packet[wgOffSender : wgOffSender+4]); got != msg.senderIndex {
		t.Errorf("sender index in the packet is %#08x, tracked as %#08x", got, msg.senderIndex)
	}
}

func TestWGInitiationMAC1(t *testing.T) {
	responder := wgKeypair(t)

	msg, err := buildWGInitiation(responder.PublicKey(), wgKeypair(t), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// mac1 is what a responder checks first; a wrong one means every probe
	// times out with no way to tell that from a dead node.
	mac1Key := wgTestHash([]byte(wgLabelMAC1), responder.PublicKey().Bytes())
	mac, err := blake2s.New128(mac1Key)
	if err != nil {
		t.Fatal(err)
	}
	mac.Write(msg.packet[:wgOffMAC1])

	if got, want := msg.packet[wgOffMAC1:wgOffMAC2], mac.Sum(nil); !bytes.Equal(got, want) {
		t.Errorf("mac1 = % x, want % x", got, want)
	}

	// mac2 stays zero until the cookie mechanism is implemented.
	if !bytes.Equal(msg.packet[wgOffMAC2:], make([]byte, wgMACSize)) {
		t.Errorf("mac2 should be zero, got % x", msg.packet[wgOffMAC2:])
	}
}

func TestWGInitiationIsFreshEachProbe(t *testing.T) {
	responder := wgKeypair(t)

	first, err := buildWGInitiation(responder.PublicKey(), wgKeypair(t), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildWGInitiation(responder.PublicKey(), wgKeypair(t), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if first.senderIndex == second.senderIndex {
		t.Error("two probes must not share a session index")
	}
	if bytes.Equal(first.packet[wgOffEphemeral:wgOffEphemeral+wgKeySize],
		second.packet[wgOffEphemeral:wgOffEphemeral+wgKeySize]) {
		t.Error("the ephemeral key must be fresh for every initiation")
	}
}

// --- the initiator's static key -------------------------------------------

func TestWGStaticKeyIsEphemeralWhenAnonymous(t *testing.T) {
	t.Setenv(wgPrivateKeyEnv, "")
	responder := wgKeypair(t)

	seen := map[string]bool{}
	for range 2 {
		static, err := wgIdentity(true)
		if err != nil {
			t.Fatal(err)
		}
		msg, err := buildWGInitiation(responder.PublicKey(), static, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := consumeInitiation(t, responder, msg.packet)
		seen[string(pub)] = true
	}

	if len(seen) != 2 {
		t.Error("in anonymous mode each probe must use a fresh static key")
	}
}

func TestWGStaticKeyFromEnvironment(t *testing.T) {
	configured := wgKeypair(t)
	t.Setenv(wgPrivateKeyEnv, base64.StdEncoding.EncodeToString(configured.Bytes()))

	responder := wgKeypair(t)
	static, err := wgIdentity(false)
	if err != nil {
		t.Fatalf("reading the configured key: %v", err)
	}
	msg, err := buildWGInitiation(responder.PublicKey(), static, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	pub, _ := consumeInitiation(t, responder, msg.packet)
	if !bytes.Equal(pub, configured.PublicKey().Bytes()) {
		t.Error("the configured key should have been used as the static identity")
	}
}

func TestWGValidateRejectsBadEnvironmentKey(t *testing.T) {
	t.Setenv(wgPrivateKeyEnv, "not-base64!!")

	target := Target{Name: "wg", Addr: "1.2.3.4:51820", Proto: "wireguard",
		Params: wgTargetParams(t, wgKeypair(t).PublicKey(), 0)}

	err := wgProber{}.Validate(target)
	if err == nil {
		t.Fatal("a malformed key in the environment must fail validation")
	}
	if !strings.Contains(err.Error(), wgPrivateKeyEnv) {
		t.Errorf("the error should name the variable, got %v", err)
	}
}

// --- params ---------------------------------------------------------------

func TestWGParamsValidation(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(wgKeypair(t).PublicKey().Bytes())

	cases := []struct {
		name string
		body string
		want string
	}{
		{"no params at all", `[{"name":"a","addr":"1.2.3.4:51820","proto":"wireguard"}]`, "public_key"},
		{"empty public key", `[{"name":"a","addr":"1.2.3.4:51820","proto":"wireguard","params":{"public_key":""}}]`, "public_key"},
		{"not base64", `[{"name":"a","addr":"1.2.3.4:51820","proto":"wireguard","params":{"public_key":"@@@"}}]`, "public_key"},
		{"wrong length", `[{"name":"a","addr":"1.2.3.4:51820","proto":"wireguard","params":{"public_key":"AAAA"}}]`, "want 32"},
		{"unknown field", fmt.Sprintf(`[{"name":"a","addr":"1.2.3.4:51820","proto":"wireguard","params":{"public_key":%q,"psk":"x"}}]`, valid), "params"},
		{"too many attempts", fmt.Sprintf(`[{"name":"a","addr":"1.2.3.4:51820","proto":"wireguard","params":{"public_key":%q,"attempts":99}}]`, valid), "attempts"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := loadTargets(writeTargets(t, c.body)); err == nil {
				t.Fatal("expected the target to be rejected")
			} else if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error should mention %q, got %v", c.want, err)
			}
		})
	}
}

func TestWGValidTargetLoads(t *testing.T) {
	t.Setenv(wgPrivateKeyEnv, base64.StdEncoding.EncodeToString(wgKeypair(t).Bytes()))

	valid := base64.StdEncoding.EncodeToString(wgKeypair(t).PublicKey().Bytes())
	body := fmt.Sprintf(`[{"name":"wg-01","addr":"1.2.3.4:51820","region":"de","proto":"wireguard",
	  "params":{"public_key":%q,"attempts":2}}]`, valid)

	targets, err := loadTargets(writeTargets(t, body))
	if err != nil {
		t.Fatalf("a valid WireGuard target was rejected: %v", err)
	}
	if targets[0].Proto != "wireguard" {
		t.Errorf("proto not parsed: %+v", targets[0])
	}
}

// --- the registered-peer requirement --------------------------------------

// TestWGRequiresRegisteredPeerAtLoad is the point of the whole check: without
// a monitoring key the handshake can never be answered, so the target has to
// be refused as a bad config rather than probed and reported as a dead node.
//
// The target deliberately points at a live responder that WOULD complete the
// probe. Failing anyway is what proves the rejection happens at load time and
// owes nothing to the network.
func TestWGRequiresRegisteredPeerAtLoad(t *testing.T) {
	t.Setenv(wgPrivateKeyEnv, "")

	addr := wgResponder(t, wgHandshakeResponse)
	peer := base64.StdEncoding.EncodeToString(wgKeypair(t).PublicKey().Bytes())
	body := fmt.Sprintf(`[{"name":"wg-fra-01","addr":%q,"proto":"wireguard","params":{"public_key":%q}}]`,
		addr, peer)

	targets, err := loadTargets(writeTargets(t, body))
	if err == nil {
		t.Fatal("a WireGuard target with no monitoring key must not load")
	}
	if targets != nil {
		t.Error("no targets should be returned when the file is rejected")
	}

	// The operator has to be able to act on this without reading the source.
	for _, want := range []string{"wg-fra-01", wgPrivateKeyEnv, "allow_anonymous", "registered"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

func TestWGAnonymousTargetLoadsWithoutAKey(t *testing.T) {
	t.Setenv(wgPrivateKeyEnv, "")

	peer := base64.StdEncoding.EncodeToString(wgKeypair(t).PublicKey().Bytes())
	body := fmt.Sprintf(`[{"name":"wg-01","addr":"1.2.3.4:51820","proto":"wireguard",
	  "params":{"public_key":%q,"allow_anonymous":true}}]`, peer)

	if _, err := loadTargets(writeTargets(t, body)); err != nil {
		t.Fatalf("an explicitly anonymous target must load: %v", err)
	}
}

func TestWGAnonymousMode(t *testing.T) {
	t.Setenv(wgPrivateKeyEnv, "")
	responder := wgKeypair(t)

	anonParams := func(t *testing.T) json.RawMessage {
		t.Helper()
		raw, err := json.Marshal(map[string]any{
			"public_key":      base64.StdEncoding.EncodeToString(responder.PublicKey().Bytes()),
			"attempts":        2,
			"allow_anonymous": true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	cases := []struct {
		name    string
		reply   func([]byte) []byte
		wantOK  bool
		wantErr string
	}{
		{
			// The expected outcome against a real node: it does not know us,
			// so it says nothing. The phase passes because it only claims the
			// initiation went out.
			name:   "silence passes",
			reply:  func([]byte) []byte { return nil },
			wantOK: true,
		},
		{
			// Still detectable without a registered peer, and still a failure.
			name:    "a non-WireGuard answer fails",
			reply:   func([]byte) []byte { return []byte("nope") },
			wantOK:  false,
			wantErr: "message type",
		},
		{
			// Stronger evidence than silence, so it cannot be a failure here.
			name: "a cookie reply passes",
			reply: func(in []byte) []byte {
				resp := make([]byte, wgCookieReplySize)
				resp[0] = wgMsgCookieReply
				copy(resp[4:8], in[wgOffSender:wgOffSender+4])
				return resp
			},
			wantOK: true,
		},
		{
			name:   "a real response still passes",
			reply:  wgHandshakeResponse,
			wantOK: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := probe(context.Background(), Target{
				Name: "wg-anon", Addr: wgResponder(t, c.reply), Proto: "wireguard",
				Params: anonParams(t),
			}, 300*time.Millisecond)

			if res.OK != c.wantOK {
				t.Fatalf("OK = %v, want %v (error %q)", res.OK, c.wantOK, res.Error)
			}
			if len(res.Phases) != 2 {
				t.Fatalf("expected both phases, got %+v", res.Phases)
			}
			// The weaker claim gets the weaker name.
			if res.Phases[1].Name != phaseWGInitiationSent {
				t.Errorf("second phase should be %q, got %q", phaseWGInitiationSent, res.Phases[1].Name)
			}
			if c.wantErr != "" && !strings.Contains(res.Error, c.wantErr) {
				t.Errorf("error %q should mention %q", res.Error, c.wantErr)
			}
			if c.wantOK && res.Error != "" {
				t.Errorf("a passing phase should carry no error, got %q", res.Error)
			}
		})
	}
}

// TestWGAnonymousMetrics pins where an anonymous result is published.
//
// It must never appear in vpnnode_up: that series is what alerts are built on,
// and an anonymous probe passing on silence would put a 1 there for a node
// nobody has heard from. vpnnode_initiation_sent carries the weaker claim
// instead, and still goes to 0 when something contradicts it.
func TestWGAnonymousMetrics(t *testing.T) {
	t.Setenv(wgPrivateKeyEnv, "")

	anonTarget := func(name, addr string) Target {
		raw, err := json.Marshal(map[string]any{
			"public_key":      base64.StdEncoding.EncodeToString(wgKeypair(t).PublicKey().Bytes()),
			"allow_anonymous": true,
			"attempts":        2,
		})
		if err != nil {
			t.Fatal(err)
		}
		return Target{Name: name, Addr: addr, Region: "de", Proto: "wireguard", Params: raw}
	}

	// A socket that receives and never answers — the normal case.
	silent := wgResponder(t, func([]byte) []byte { return nil })

	// A port bound and released, so the kernel answers with ICMP unreachable.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := pc.LocalAddr().String()
	pc.Close()

	results := []Result{
		probe(context.Background(), anonTarget("wg-silent", silent), 300*time.Millisecond),
		probe(context.Background(), anonTarget("wg-closed", closed), 300*time.Millisecond),
	}

	var buf bytes.Buffer
	writeProm(&buf, results)
	out := buf.String()

	for _, want := range []string{
		"# TYPE vpnnode_initiation_sent gauge",
		`vpnnode_initiation_sent{node="wg-silent",region="de"} 1`,
		`vpnnode_initiation_sent{node="wg-closed",region="de"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n---\n%s", want, out)
		}
	}

	// Neither target may show up in the liveness series, in either direction.
	for _, unwanted := range []string{
		`vpnnode_up{node="wg-silent"`,
		`vpnnode_up{node="wg-closed"`,
	} {
		if strings.Contains(out, unwanted) {
			t.Errorf("an anonymous target must not appear in vpnnode_up: %q\n---\n%s", unwanted, out)
		}
	}
}

// A target with a registered key keeps making the liveness claim, so the
// exclusion has to be about the anonymous mode and not about WireGuard.
func TestWGStrictModeStillReportsUp(t *testing.T) {
	t.Setenv(wgPrivateKeyEnv, base64.StdEncoding.EncodeToString(wgKeypair(t).Bytes()))
	responder := wgKeypair(t)

	res := probe(context.Background(), Target{
		Name: "wg-strict", Addr: wgResponder(t, wgHandshakeResponse), Region: "de",
		Proto: "wireguard", Params: wgTargetParams(t, responder.PublicKey(), 1),
	}, 2*time.Second)

	var buf bytes.Buffer
	writeProm(&buf, []Result{res})
	out := buf.String()

	if !strings.Contains(out, `vpnnode_up{node="wg-strict",region="de"} 1`) {
		t.Errorf("a handshake-confirmed node belongs in vpnnode_up\n---\n%s", out)
	}
	if strings.Contains(out, `vpnnode_initiation_sent{node="wg-strict"`) {
		t.Errorf("a strict target must not be reported as initiation-only\n---\n%s", out)
	}
}

// TestWGAnonymousFailsOnRefusedPort keeps the mode from degenerating into "the
// packet left the host, therefore fine". An ICMP port-unreachable says there
// is no listener, and that must still be a failure.
func TestWGAnonymousFailsOnRefusedPort(t *testing.T) {
	t.Setenv(wgPrivateKeyEnv, "")

	// Bind and release a port to get one that is almost certainly closed.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()

	params, err := json.Marshal(map[string]any{
		"public_key":      base64.StdEncoding.EncodeToString(wgKeypair(t).PublicKey().Bytes()),
		"allow_anonymous": true,
		"attempts":        2,
	})
	if err != nil {
		t.Fatal(err)
	}

	res := probe(context.Background(),
		Target{Name: "wg-closed", Addr: addr, Proto: "wireguard", Params: params},
		300*time.Millisecond)

	if res.OK {
		t.Fatalf("a refused port must fail even in anonymous mode: %+v", res.Phases)
	}
	if !strings.HasPrefix(res.Error, phaseWGInitiationSent+":") {
		t.Errorf("failure should be attributed to the initiation phase, got %q", res.Error)
	}
}

// --- probing against a local responder ------------------------------------

// wgResponder starts a UDP listener that answers initiations according to
// reply, which is given the received packet and returns the datagram to send
// back (nil for silence).
func wgResponder(t *testing.T, reply func(initiation []byte) []byte) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return // listener closed
			}
			if out := reply(append([]byte(nil), buf[:n]...)); out != nil {
				pc.WriteTo(out, from)
			}
		}
	}()

	return pc.LocalAddr().String()
}

// wgHandshakeResponse builds a type 2 message echoing the initiation's sender
// index as its receiver index. Only the fields this prober inspects are
// meaningful; the rest is padding, which is exactly the prober's stated limit.
func wgHandshakeResponse(initiation []byte) []byte {
	resp := make([]byte, wgResponseSize)
	resp[0] = wgMsgResponse
	binary.LittleEndian.PutUint32(resp[4:8], 0x11223344) // responder's own index
	copy(resp[8:12], initiation[wgOffSender:wgOffSender+4])
	return resp
}

func TestWGProbe(t *testing.T) {
	// A registered monitoring key is the supported configuration, and the only
	// one in which a handshake response can arrive at all.
	t.Setenv(wgPrivateKeyEnv, base64.StdEncoding.EncodeToString(wgKeypair(t).Bytes()))
	responder := wgKeypair(t)

	cases := []struct {
		name    string
		reply   func([]byte) []byte
		wantOK  bool
		wantErr string
	}{
		{
			// The normal outcome against a real server that does not know us,
			// and the reason this prober's silence is ambiguous.
			name:    "silent",
			reply:   func([]byte) []byte { return nil },
			wantErr: "timeout",
		},
		{
			name:    "garbage",
			reply:   func([]byte) []byte { return []byte("definitely not wireguard") },
			wantErr: "message type",
		},
		{
			name:   "valid handshake response",
			reply:  wgHandshakeResponse,
			wantOK: true,
		},
		{
			name: "response for somebody else's session",
			reply: func(in []byte) []byte {
				resp := wgHandshakeResponse(in)
				binary.LittleEndian.PutUint32(resp[8:12], 0xdeadbeef)
				return resp
			},
			wantErr: "session",
		},
		{
			name: "cookie reply",
			reply: func(in []byte) []byte {
				resp := make([]byte, wgCookieReplySize)
				resp[0] = wgMsgCookieReply
				copy(resp[4:8], in[wgOffSender:wgOffSender+4])
				return resp
			},
			wantErr: "cookie reply",
		},
		{
			name: "truncated response",
			reply: func(in []byte) []byte {
				return wgHandshakeResponse(in)[:40]
			},
			wantErr: "want 92",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addr := wgResponder(t, c.reply)

			res := probe(context.Background(), Target{
				Name:   "wg-01",
				Addr:   addr,
				Proto:  "wireguard",
				Params: wgTargetParams(t, responder.PublicKey(), 2),
			}, 400*time.Millisecond)

			if res.OK != c.wantOK {
				t.Fatalf("OK = %v, want %v (error %q)", res.OK, c.wantOK, res.Error)
			}

			// The send phase always passes here: the datagram left the host.
			// It is the handshake phase that carries the verdict.
			if len(res.Phases) != 2 {
				t.Fatalf("expected both phases, got %+v", res.Phases)
			}
			if !res.Phases[0].OK || res.Phases[0].Name != phaseUDPSend {
				t.Errorf("send phase should have passed: %+v", res.Phases[0])
			}
			if res.Phases[1].Name != phaseWGHandshake {
				t.Errorf("second phase should be %q, got %q", phaseWGHandshake, res.Phases[1].Name)
			}

			if c.wantErr != "" && !strings.Contains(res.Error, c.wantErr) {
				t.Errorf("error %q should mention %q", res.Error, c.wantErr)
			}
			if c.wantErr != "" && !strings.HasPrefix(res.Error, phaseWGHandshake+":") {
				t.Errorf("failure should be attributed to the handshake phase, got %q", res.Error)
			}
		})
	}
}

// TestWGProbeSendsAValidInitiation closes the loop: the bytes that actually go
// on the wire during a probe are the ones a responder can decrypt.
func TestWGProbeSendsAValidInitiation(t *testing.T) {
	t.Setenv(wgPrivateKeyEnv, base64.StdEncoding.EncodeToString(wgKeypair(t).Bytes()))
	responder := wgKeypair(t)

	received := make(chan []byte, 1)
	addr := wgResponder(t, func(in []byte) []byte {
		select {
		case received <- in:
		default:
		}
		return wgHandshakeResponse(in)
	})

	res := probe(context.Background(), Target{
		Name:   "wg-01",
		Addr:   addr,
		Proto:  "wireguard",
		Params: wgTargetParams(t, responder.PublicKey(), 1),
	}, 2*time.Second)

	if !res.OK {
		t.Fatalf("probe failed: %q", res.Error)
	}

	select {
	case packet := <-received:
		consumeInitiation(t, responder, packet) // fails the test if it does not decrypt
	case <-time.After(time.Second):
		t.Fatal("the responder never saw an initiation")
	}
}

// A UDP result carries no TCP/TLS fields, and WireGuard is no exception.
func TestWGResultShape(t *testing.T) {
	t.Setenv(wgPrivateKeyEnv, base64.StdEncoding.EncodeToString(wgKeypair(t).Bytes()))
	responder := wgKeypair(t)
	addr := wgResponder(t, wgHandshakeResponse)

	res := probe(context.Background(), Target{
		Name: "wg-01", Addr: addr, Region: "de", Proto: "wireguard",
		Params: wgTargetParams(t, responder.PublicKey(), 1),
	}, 2*time.Second)

	if res.TCPOK != nil || res.TLSOK != nil || res.CertMatch != nil {
		t.Error("a WireGuard result must not claim anything about TCP or TLS")
	}
	if len(res.Phases) != 2 || res.Phases[1].Name != phaseWGHandshake {
		t.Fatalf("unexpected phases: %+v", res.Phases)
	}
	if res.Params != nil {
		t.Error("params must not be echoed into the result")
	}
}
