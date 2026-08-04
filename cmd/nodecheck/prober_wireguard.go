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
	"errors"
	"fmt"
	"hash"
	"os"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

// wgProber sends a real WireGuard handshake initiation (Noise IK, message
// type 1) and waits for a handshake response (type 2). Unlike proto "udp",
// which accepts any datagram as proof of life, this one confirms that what is
// listening actually speaks WireGuard.
//
// # What a response does and does not prove
//
// Read the phases carefully before wiring an alert to this prober:
//
//   - "udp" passing means only that the datagram left the host.
//   - "handshake" passing means a WireGuard responder answered our exact
//     session, so the port is a live WireGuard endpoint that accepted us.
//   - "handshake" failing means the endpoint did not complete our session:
//     the port is filtered, the node is down, or it no longer accepts the
//     monitoring peer.
//
// # Why a registered peer is mandatory
//
// WireGuard is deliberately silent to peers it does not recognise — a design
// goal of the protocol, not a bug to work around. A responder decrypts the
// initiator's static public key, finds no such peer, and drops the packet
// without a word. So a probe using an ad-hoc key could never report anything
// but a timeout, and a whole fleet would show up as down because of a missing
// environment variable.
//
// The prober therefore refuses such targets at load time (see wgIdentity).
// Register one monitoring public key as a peer across the fleet and hand the
// prober its private key through NODECHECK_WG_PRIVATE_KEY (base64, as wg(8)
// prints it) — environment only, never a flag or the targets file, for the
// same reason as the push token: argv is world-readable and config files get
// copied around.
//
// # allow_anonymous
//
// A target may opt out with "allow_anonymous": true, for a node where
// registering a monitoring peer is not possible. The initiator's static key is
// then generated fresh per probe, and the second phase is renamed
// "initiation-sent" because that is all it can claim: a well-formed initiation
// left the host and nothing contradicted it. Silence passes in this mode, so
// the phase is NOT evidence that the node is alive. What it still detects is
// an ICMP port-unreachable and an answer that is not WireGuard.
//
// # Not implemented
//
// MAC2 and the cookie mechanism are absent: mac2 is sent as zeroes. A
// responder that is under load replies with a cookie (type 3) instead of a
// handshake response, and this prober reports that as a distinct, named
// failure rather than as silence — it is still proof that a WireGuard
// responder is there. Implementing mac2 means retrying with the returned
// cookie, which is worth doing only if loaded responders turn out to be
// common in practice.
//
// The response is validated by shape and by session: type 2, correct length,
// and our own sender index echoed back. Verifying its `encrypted_nothing`
// field would additionally prove the responder holds the private key for the
// configured public key; that is the natural next step and needs the chaining
// key this code already computes.
type wgProber struct{}

func init() { register(wgProber{}) }

func (wgProber) Kind() string { return "wireguard" }

// phaseWGHandshake replaces "response" for this prober: it claims something
// stronger than "a datagram came back", and the phase name is what an
// operator reads first.
//
// phaseWGInitiationSent is its allow_anonymous counterpart, named to promise
// less: a valid initiation went out and nothing contradicted it. It is not
// evidence that the node is alive.
const (
	phaseWGHandshake      = "handshake"
	phaseWGInitiationSent = "initiation-sent"
)

// Protocol constants, from the WireGuard whitepaper.
const (
	wgConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	wgIdentifier   = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	wgLabelMAC1    = "mac1----"
)

const (
	wgMsgInitiation  = 1
	wgMsgResponse    = 2
	wgMsgCookieReply = 3

	// Fixed sizes. WireGuard messages are constant-length by design, which is
	// itself part of its traffic profile.
	wgInitiationSize  = 148
	wgResponseSize    = 92
	wgCookieReplySize = 64

	wgKeySize = 32
	wgMACSize = 16
)

// wgPrivateKeyEnv optionally supplies the initiator's static private key. See
// the type comment for why it exists and why it is env-only.
const wgPrivateKeyEnv = "NODECHECK_WG_PRIVATE_KEY"

// wgParams is the per-target `params` object for proto "wireguard".
type wgParams struct {
	// PublicKey is the responder's static public key, base64 as wg(8) prints
	// it. Public by definition — it is what the peer publishes.
	PublicKey string `json:"public_key"`

	// Attempts is the total number of initiations sent, not the number of
	// retries. Zero selects the default.
	Attempts int `json:"attempts,omitempty"`

	// AllowAnonymous permits probing a node that has not registered our
	// monitoring key, downgrading the second phase to a claim about the
	// packet we sent rather than about the node. See wgConfig.anonymous.
	AllowAnonymous bool `json:"allow_anonymous,omitempty"`
}

// wgConfig is the validated form of wgParams.
type wgConfig struct {
	peer     *ecdh.PublicKey
	attempts int

	// anonymous means the operator has accepted that this target cannot
	// confirm liveness: without a registered peer the responder will not
	// answer, so silence stops being evidence of anything.
	anonymous bool
}

func parseWGParams(raw json.RawMessage) (wgConfig, error) {
	var p wgParams
	if len(raw) == 0 {
		return wgConfig{}, errors.New(`params: "public_key" is required`)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return wgConfig{}, fmt.Errorf("params: %w", err)
	}

	if p.PublicKey == "" {
		return wgConfig{}, errors.New(`params: "public_key" is required`)
	}
	key, err := base64.StdEncoding.DecodeString(p.PublicKey)
	if err != nil {
		return wgConfig{}, fmt.Errorf("params: public_key: %w", err)
	}
	if len(key) != wgKeySize {
		return wgConfig{}, fmt.Errorf("params: public_key: got %d bytes, want %d", len(key), wgKeySize)
	}
	peer, err := ecdh.X25519().NewPublicKey(key)
	if err != nil {
		return wgConfig{}, fmt.Errorf("params: public_key: %w", err)
	}

	attempts := p.Attempts
	switch {
	case attempts == 0:
		attempts = defaultUDPAttempts
	case attempts < 0:
		return wgConfig{}, fmt.Errorf("params: attempts must be positive, got %d", attempts)
	case attempts > maxUDPAttempts:
		return wgConfig{}, fmt.Errorf("params: attempts must be at most %d, got %d", maxUDPAttempts, attempts)
	}

	return wgConfig{peer: peer, attempts: attempts, anonymous: p.AllowAnonymous}, nil
}

func (wgProber) Validate(t Target) error {
	if t.Addr == "" {
		return errors.New("addr is required")
	}
	cfg, err := parseWGParams(t.Params)
	if err != nil {
		return err
	}
	// Resolving the identity here is the whole point: without a registered
	// monitoring peer the handshake can never be answered, and letting that
	// through would report a configuration mistake as a node that is down.
	_, err = wgIdentity(cfg.anonymous)
	return err
}

func (wgProber) Probe(ctx context.Context, t Target, timeout time.Duration) Outcome {
	var out Outcome

	// Anything that fails here is a configuration problem, not a network one,
	// and loadTargets has already rejected it. Reported on the send phase so a
	// caller that skipped validation still gets a result rather than a panic.
	cfg, err := parseWGParams(t.Params)
	if err != nil {
		out.Phases = append(out.Phases, Phase{Name: phaseUDPSend, Err: err.Error()})
		return out
	}
	// Set before anything else can fail, so an anonymous target is routed to
	// the same metric family however far the probe gets. A node that changed
	// which series it reports into depending on where it broke would be two
	// different nodes to a dashboard.
	out.NoLivenessClaim = cfg.anonymous

	static, err := wgIdentity(cfg.anonymous)
	if err != nil {
		out.Phases = append(out.Phases, Phase{Name: phaseUDPSend, Err: err.Error()})
		return out
	}
	msg, err := buildWGInitiation(cfg.peer, static, time.Now())
	if err != nil {
		out.Phases = append(out.Phases, Phase{Name: phaseUDPSend, Err: err.Error()})
		return out
	}

	exchange := udpExchange{
		addr:      t.Addr,
		payload:   msg.packet,
		attempts:  cfg.attempts,
		sendPhase: phaseUDPSend,
		respPhase: phaseWGHandshake,
		accept:    msg.validateResponse,
	}

	if cfg.anonymous {
		// The phase is renamed because it now claims something weaker, and the
		// name is what an operator reads first. Silence passes — an
		// unregistered peer is met with silence by design — but a refused port
		// or a non-WireGuard answer still fails, and those are the two things
		// this mode can actually detect.
		exchange.respPhase = phaseWGInitiationSent
		exchange.accept = msg.acceptAnonymous
		exchange.silenceOK = true
	}

	out.Phases, _ = exchange.run(ctx, timeout)
	return out
}

// wgIdentity returns the initiator's static key.
//
// Without NODECHECK_WG_PRIVATE_KEY there is no registered monitoring peer, and
// a WireGuard responder answers an unknown peer with silence — so a probe
// built on an ad-hoc key could never report anything but a timeout. Refusing
// the target is the only honest option: a fleet reported as uniformly down
// because of a missing environment variable is a configuration error wearing
// an outage's clothes.
//
// allow_anonymous is the deliberate opt-out, for a node where registering a
// monitoring peer is not possible or not wanted.
func wgIdentity(anonymous bool) (*ecdh.PrivateKey, error) {
	raw := os.Getenv(wgPrivateKeyEnv)
	if raw == "" {
		if !anonymous {
			return nil, fmt.Errorf(
				"needs a registered monitoring peer: set %s to the private key whose public key "+
					"is registered as a peer on this node (see README \"wireguard\"), or set "+
					`"allow_anonymous": true in params to send an initiation that cannot confirm `+
					"the node is alive",
				wgPrivateKeyEnv)
		}
		// Anonymous: a fresh key per probe, so nothing secret is needed and
		// nothing is reused between nodes.
		return ecdh.X25519().GenerateKey(rand.Reader)
	}
	return wgParsePrivateKey(raw)
}

func wgParsePrivateKey(raw string) (*ecdh.PrivateKey, error) {
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", wgPrivateKeyEnv, err)
	}
	if len(key) != wgKeySize {
		return nil, fmt.Errorf("%s: got %d bytes, want %d", wgPrivateKeyEnv, len(key), wgKeySize)
	}
	priv, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", wgPrivateKeyEnv, err)
	}
	return priv, nil
}

// wgInitiation is an assembled message together with the session state needed
// to recognise its answer.
type wgInitiation struct {
	packet      []byte
	senderIndex uint32
}

// buildWGInitiation assembles a handshake initiation.
//
// The layout is fixed at 148 bytes:
//
//	type u8 | reserved [3]u8 | sender u32 | ephemeral [32]u8 |
//	encrypted_static [48]u8 | encrypted_timestamp [28]u8 | mac1 [16]u8 | mac2 [16]u8
//
// now is a parameter rather than read inside so tests can pin the timestamp.
func buildWGInitiation(peer *ecdh.PublicKey, static *ecdh.PrivateKey, now time.Time) (wgInitiation, error) {
	peerPub := peer.Bytes()

	// ck = HASH(CONSTRUCTION); h = HASH(HASH(ck || IDENTIFIER) || responder_pub)
	ck := wgHash([]byte(wgConstruction))
	hi := wgHash(ck[:], []byte(wgIdentifier))
	h := wgHash(hi[:], peerPub)

	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return wgInitiation{}, fmt.Errorf("generating ephemeral key: %w", err)
	}
	ephPub := eph.PublicKey().Bytes()

	// The sender index is ours to choose and is what the responder echoes back
	// as its receiver index. Random rather than sequential so two probes of
	// the same node cannot be confused for each other.
	var idx [4]byte
	if _, err := rand.Read(idx[:]); err != nil {
		return wgInitiation{}, fmt.Errorf("generating sender index: %w", err)
	}
	senderIndex := binary.LittleEndian.Uint32(idx[:])

	packet := make([]byte, 0, wgInitiationSize)
	packet = append(packet, wgMsgInitiation, 0, 0, 0)
	packet = binary.LittleEndian.AppendUint32(packet, senderIndex)
	packet = append(packet, ephPub...)

	h = wgHash(h[:], ephPub)
	ck = wgKDF1(ck, ephPub)

	// encrypted_static: our static public key, under a key derived from
	// DH(ephemeral, responder_static).
	dhEphemeral, err := eph.ECDH(peer)
	if err != nil {
		return wgInitiation{}, fmt.Errorf("ephemeral DH: %w", err)
	}
	ck, key := wgKDF2(ck, dhEphemeral)
	encryptedStatic, err := wgSeal(key, static.PublicKey().Bytes(), h[:])
	if err != nil {
		return wgInitiation{}, err
	}
	packet = append(packet, encryptedStatic...)
	h = wgHash(h[:], encryptedStatic)

	// encrypted_timestamp: a TAI64N stamp under a key derived from
	// DH(our_static, responder_static). This is what gives the responder its
	// replay protection.
	dhStatic, err := static.ECDH(peer)
	if err != nil {
		return wgInitiation{}, fmt.Errorf("static DH: %w", err)
	}
	ck, key = wgKDF2(ck, dhStatic)
	encryptedTimestamp, err := wgSeal(key, wgTAI64N(now), h[:])
	if err != nil {
		return wgInitiation{}, err
	}
	packet = append(packet, encryptedTimestamp...)
	// ck and h would carry on into verifying the response; see the type comment.
	_, _ = ck, wgHash(h[:], encryptedTimestamp)

	// mac1 over everything so far, keyed by the responder's public key. It is
	// not optional: a responder silently discards any packet whose mac1 does
	// not check out, so omitting it turns every probe into a timeout.
	mac1Key := wgHash([]byte(wgLabelMAC1), peerPub)
	mac, err := blake2s.New128(mac1Key[:])
	if err != nil {
		return wgInitiation{}, fmt.Errorf("mac1: %w", err)
	}
	mac.Write(packet)
	packet = append(packet, mac.Sum(nil)...)

	// mac2 is zero: it is only required once a responder is under load and has
	// issued a cookie. See "Not implemented" in the type comment.
	packet = append(packet, make([]byte, wgMACSize)...)

	if len(packet) != wgInitiationSize {
		// A wrong length would be silently dropped by the responder and look
		// exactly like an outage, so fail loudly instead.
		return wgInitiation{}, fmt.Errorf("built a %d-byte initiation, want %d", len(packet), wgInitiationSize)
	}

	return wgInitiation{packet: packet, senderIndex: senderIndex}, nil
}

// validateResponse decides whether a datagram is the answer to this initiation.
func (init wgInitiation) validateResponse(reply []byte) error {
	if len(reply) == 0 {
		return errors.New("empty datagram")
	}

	switch reply[0] {
	case wgMsgResponse:
		if len(reply) != wgResponseSize {
			return fmt.Errorf("handshake response is %d bytes, want %d", len(reply), wgResponseSize)
		}
		// Bytes 8:12 are the receiver index: the sender index we chose,
		// echoed back. Without this check any WireGuard traffic arriving on
		// the socket would pass, including an answer to somebody else.
		if got := binary.LittleEndian.Uint32(reply[8:12]); got != init.senderIndex {
			return fmt.Errorf("handshake response is for session %#08x, ours is %#08x", got, init.senderIndex)
		}
		return nil

	case wgMsgCookieReply:
		// A real WireGuard responder, but one that is under load and wants
		// mac2. Worth naming precisely: it proves the endpoint is alive and
		// speaks the protocol, which silence never would.
		if len(reply) == wgCookieReplySize {
			return errors.New("cookie reply: the responder is under load and requires mac2, which this probe does not implement")
		}
		return fmt.Errorf("malformed cookie reply: %d bytes, want %d", len(reply), wgCookieReplySize)

	default:
		return fmt.Errorf("not a WireGuard handshake response: message type %d, %d bytes", reply[0], len(reply))
	}
}

// acceptAnonymous is validateResponse relaxed for allow_anonymous mode.
//
// A cookie reply counts as an answer here. In this mode we could not have
// completed a handshake anyway, so a responder telling us it is under load is
// the strongest confirmation available — treating it as a failure while
// treating silence as success would be exactly backwards.
func (init wgInitiation) acceptAnonymous(reply []byte) error {
	err := init.validateResponse(reply)
	if err == nil {
		return nil
	}
	if len(reply) == wgCookieReplySize && reply[0] == wgMsgCookieReply {
		return nil
	}
	return err
}

// --- Noise primitives -----------------------------------------------------
//
// HASH is BLAKE2s-256, HMAC is HMAC-BLAKE2s-256, AEAD is ChaCha20-Poly1305.
// Only BLAKE2s and ChaCha20-Poly1305 come from x/crypto; X25519 is stdlib
// crypto/ecdh.

func wgBlake2s() hash.Hash {
	h, err := blake2s.New256(nil)
	// New256 only fails on an oversized key, and there is no key here.
	if err != nil {
		panic("nodecheck: blake2s: " + err.Error())
	}
	return h
}

func wgHash(parts ...[]byte) [32]byte {
	h := wgBlake2s()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func wgHMAC(key, data []byte) [32]byte {
	m := hmac.New(wgBlake2s, key)
	m.Write(data)
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

// wgKDF1 and wgKDF2 are the Noise HKDF: temp = HMAC(ck, input), then each
// output is HMAC(temp, previous_output || counter).
func wgKDF1(ck [32]byte, input []byte) [32]byte {
	temp := wgHMAC(ck[:], input)
	return wgHMAC(temp[:], []byte{0x01})
}

func wgKDF2(ck [32]byte, input []byte) (k1, k2 [32]byte) {
	temp := wgHMAC(ck[:], input)
	k1 = wgHMAC(temp[:], []byte{0x01})

	second := make([]byte, 0, len(k1)+1)
	second = append(second, k1[:]...)
	second = append(second, 0x02)
	k2 = wgHMAC(temp[:], second)
	return k1, k2
}

// wgSeal encrypts with the all-zero nonce: handshake messages are counter 0,
// and each one uses a freshly derived key, so the nonce is never reused.
func wgSeal(key [32]byte, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("aead: %w", err)
	}
	var nonce [chacha20poly1305.NonceSize]byte
	return aead.Seal(nil, nonce[:], plaintext, aad), nil
}

// wgTAI64N renders a timestamp in the 12-byte external TAI64N format
// WireGuard uses for replay protection.
func wgTAI64N(now time.Time) []byte {
	var ts [12]byte
	// 2^62 plus ten leap seconds is the TAI64 epoch offset from Unix time.
	binary.BigEndian.PutUint64(ts[0:8], 0x400000000000000a+uint64(now.Unix()))
	binary.BigEndian.PutUint32(ts[8:12], uint32(now.Nanosecond()))
	return ts[:]
}
