package network

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"packet-bot/internal/crypto/xtea"
)

// Login service constants. Port 43594 multiplexes two services by the first
// byte sent: 15 is the JS5 update server (see js5_handshake.go), 14 is the game
// login service that actually authenticates an account into a world.
const (
	serviceGameLogin = 14 // initial handshake byte for the login service
	loginTypeNew     = 16 // fresh login
	loginTypeReconn  = 18 // reconnecting to an existing session
)

// LoginConfig carries everything needed to authenticate one account.
//
// Several fields are revision-specific and Jagex-controlled; defaults here are
// reasonable placeholders, but Revision, RSA and ArchiveCRCs MUST match the
// live client you target or the server will reject the login. See the comments
// on each field.
type LoginConfig struct {
	Username string
	Password string

	// Revision is the client/cache revision (same value used for the JS5
	// handshake). Must match the live game version.
	Revision uint32

	// RSA is Jagex's public key for this revision. If nil, login cannot encrypt
	// its secure block and Login returns an error rather than sending plaintext
	// secrets.
	RSA *RSAPublicKey

	// ArchiveCRCs are the per-index cache CRCs the server validates. The exact
	// count and values are revision-specific; an all-zero table is sent if this
	// is nil, which most live servers reject. Populate from your cache.
	ArchiveCRCs []uint32

	// Reconnecting selects login type 18 instead of 16.
	Reconnecting bool

	// AuthCode is an optional TOTP/authenticator code (0 if unused).
	AuthCode uint32

	// Optional client-detail values used in the login frame. Zero values keep
	// conservative defaults close to the stock fixed-size client.
	ClientOption1 byte
	ClientOption2 byte
	AccountFlags  byte
	WindowWidth   uint16
	WindowHeight  uint16
	PlatformInfo  []byte
	ClientToken   string
	// GameSessionToken is the short token returned by
	// auth.runescape.com/game-session/v1/tokens. Jagex-account logins write this
	// token (client.pk) into the RSA block; ClientToken/fr.gf still belongs in
	// the XTEA secure zone.
	GameSessionToken string
	DeviceID         uint32
	ArchiveBlob      []byte

	// PKMinter, when set, is called at the start of Login to mint a fresh
	// GameSessionToken (client.pk) just before the login frame is built and
	// sent. The pk is short-lived, so minting just-in-time (rather than minutes
	// earlier in a separate step) avoids the token expiring in transit through a
	// slow connect/handshake. The returned token replaces GameSessionToken for
	// this login only. A minter error aborts the login.
	PKMinter func() (string, error)

	// MachineInfo, when set, replaces the built-in machine-info blob (the
	// kg.ps/vu telemetry block). Use it to replay a blob captured from a live
	// RuneLite login (tools/agent) byte-for-byte. Nil uses buildMachineInfoBlob
	// unless RequireCapturedMachineInfo is set (production Docker).
	MachineInfo []byte

	// RequireCapturedMachineInfo refuses the goldenMachineInfo fallback when true.
	// Set this in Docker/production or after a live session handoff.
	RequireCapturedMachineInfo bool

	// CaptureFrame and CaptureRSAPlain, when both set, route Login through
	// LoginFromCapture (byte-identical XTEA zone + paired pk from host capture).
	CaptureFrame    []byte
	CaptureRSAPlain []byte

	// UsePlainCRCs, when true, writes cache CRCs sequentially (indices 0-22,
	// big-endian) instead of the client's scrambled order/endianness. Diagnostic
	// only.
	UsePlainCRCs bool

	// Timeout bounds the whole login exchange.
	Timeout time.Duration
}

// LoginResult holds the ISAAC ciphers negotiated by a successful login. The
// session installs these on its encoder/decoder so subsequent opcodes are
// scrambled in step with the server.
type LoginResult struct {
	OutCipher   *ISAAC // client -> server opcode scrambling (session keys as-is)
	InCipher    *ISAAC // server -> client opcode descrambling (session keys + 50)
	PlayerIndex uint16 // local player slot in the active world (2-byte BE ushort)
}

// loginError maps a server response code to a descriptive error.
func loginError(code byte) error {
	switch code {
	case 2:
		return nil // success
	case 3:
		return errors.New("login rejected: invalid username or password (code 3)")
	case 4:
		return errors.New("login rejected: account disabled/banned (code 4)")
	case 5:
		return errors.New("login rejected: account already logged in (code 5)")
	case 6:
		return errors.New("login rejected: client out of date (code 6)")
	case 7:
		return errors.New("login rejected: world is full (code 7)")
	case 8:
		return errors.New("login rejected: login server offline (code 8)")
	case 9:
		return errors.New("login rejected: too many connections from your address (code 9)")
	case 10:
		return errors.New("login rejected: bad session id — CLIENT_TOKEN/GAME_SESSION_TOKEN expired or invalid (code 10)")
	case 11:
		return errors.New("login rejected: account locked (code 11)")
	case 12:
		return errors.New("login rejected: members-only world or character in members area (code 12)")
	case 13:
		return errors.New("login rejected: could not complete login, try a different world (code 13)")
	case 14:
		return errors.New("login rejected: server updating, retry in one minute (code 14)")
	case 16:
		return errors.New("login rejected: too many login attempts (code 16)")
	case 22:
		return errors.New("login rejected: malformed login packet — frame structure may have changed (code 22)")
	case 63:
		return errors.New("login rejected: invalid or expired Jagex session token (code 63)")
	default:
		return fmt.Errorf("login rejected: server response code %d", code)
	}
}

// Login performs the full game-login handshake over conn and, on success,
// returns the negotiated ISAAC ciphers. It does not close conn.
func Login(conn net.Conn, cfg LoginConfig) (*LoginResult, error) {
	if cfg.RSA == nil {
		return nil, errors.New("login: no RSA public key configured (set RSA_MODULUS/RSA_EXPONENT) — refusing to send credentials unencrypted")
	}
	if len(cfg.CaptureFrame) > 0 && len(cfg.CaptureRSAPlain) > 0 {
		return LoginFromCapture(conn, cfg.CaptureFrame, cfg.CaptureRSAPlain, cfg.RSA, cfg.Timeout)
	}
	if cfg.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(cfg.Timeout))
		defer conn.SetDeadline(time.Time{})
	}

	// Just-in-time pk mint: refresh the short-lived game-session token right
	// before the handshake so it is only seconds old when the login frame is
	// sent. Done before loginHandshake so the (slow) HTTPS mint does not hold the
	// server's login handshake open past its timeout.
	if cfg.PKMinter != nil {
		pk, err := cfg.PKMinter()
		if err != nil {
			return nil, fmt.Errorf("login: just-in-time pk mint failed: %w", err)
		}
		cfg.GameSessionToken = pk
	}

	serverSeed, err := loginHandshake(conn)
	if err != nil {
		return nil, err
	}

	// The four ISAAC session-key words are all client-generated randoms (the
	// decompiled client's var6_23 = pi.lu.nextInt() x4). They double as the
	// XTEA key for the secure login zone and as the ISAAC opcode-cipher seed.
	// The server seed contributes only the 64-bit value packed inside the RSA
	// block (the client's fn(bj.lz) write).
	payload, seeds, err := buildLoginPayload(cfg, cfg.RSA, serverSeed)
	if err != nil {
		return nil, err
	}

	loginType := byte(loginTypeNew)
	if cfg.Reconnecting {
		loginType = loginTypeReconn
	}

	frame := make([]byte, 0, 3+len(payload))
	frame = append(frame, loginType)
	frame = append(frame, byte(len(payload)>>8), byte(len(payload)))
	frame = append(frame, payload...)
	if _, err := conn.Write(frame); err != nil {
		return nil, fmt.Errorf("login: write login block: %w", err)
	}

	playerIndex, inCipher, outCipher, err := HandleLoginResponse(conn, seeds)
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		OutCipher:   outCipher,
		InCipher:    inCipher,
		PlayerIndex: playerIndex,
	}, nil
}

// HandleLoginResponse processes Layer 4 (response code) and Layer 5 (ISAAC init)
// after the RSA login block has been sent. Verified against the injected
// 1.12-27 client (class yk = IsaacCipher): the writer cipher (df.av) is seeded
// with the four session-key ints as-is; the reader cipher (xj.ag) is seeded with
// each int offset by 50.
func HandleLoginResponse(conn net.Conn, sessionKeys []uint32) (uint16, *ISAAC, *ISAAC, error) {
	respBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return 0, nil, nil, fmt.Errorf("login: read response code: %w", err)
	}
	if err := loginError(respBuf[0]); err != nil {
		return 0, nil, nil, err
	}

	metaBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, metaBuf); err != nil {
		return 0, nil, nil, fmt.Errorf("login: read player index: %w", err)
	}
	playerIndex := binary.BigEndian.Uint16(metaBuf)

	outCipher := NewISAAC(sessionKeys)

	inSeed := make([]uint32, len(sessionKeys))
	for i, v := range sessionKeys {
		inSeed[i] = v + 50
	}
	inCipher := NewISAAC(inSeed)

	return playerIndex, inCipher, outCipher, nil
}

// LoginHandshake performs the game-login service handshake and returns the
// 8-byte server seed. Exported for diagnostics.
func LoginHandshake(conn net.Conn) (uint64, error) {
	return loginHandshake(conn)
}

const loginBodyHead = 15 // rev, 1, sentinel, gd, gy, pad

// rsaPlaintextPKOffset is where the null-terminated client.pk string starts in a
// captured xi.db RSA plaintext block (after the 0x01 header, seeds, server seed,
// auth type, reserved bytes, and rsaFlag).
const rsaPlaintextPKOffset = 31

// PatchRSAPlaintextGameSessionToken replaces client.pk in a captured RSA plaintext
// block while preserving XTEA/ISAAC seeds. Used after wire-block: mint a fresh pk,
// patch rsa_plaintext.txt, then LoginFromCapture with the captured XTEA zone.
func PatchRSAPlaintextGameSessionToken(rsaPlain []byte, pk string) ([]byte, error) {
	if len(rsaPlain) < rsaPlaintextPKOffset+1 {
		return nil, fmt.Errorf("login: rsa plaintext too short to patch pk (%d bytes)", len(rsaPlain))
	}
	if rsaPlain[0] != 1 {
		return nil, fmt.Errorf("login: rsa plaintext missing 0x01 header (got 0x%02x)", rsaPlain[0])
	}
	if pk == "" {
		return nil, errors.New("login: empty pk for RSA patch")
	}
	out := make([]byte, 0, rsaPlaintextPKOffset+len(pk)+1)
	out = append(out, rsaPlain[:rsaPlaintextPKOffset]...)
	out = append(out, pk...)
	out = append(out, 0)
	return out, nil
}

// LoginSeedsFromRSAPlaintext extracts the four XTEA/ISAAC seed words from the
// captured xi.db RSA plaintext block (tools/agent rsa_plaintext.txt).
func LoginSeedsFromRSAPlaintext(rsaPlain []byte) ([]uint32, error) {
	if len(rsaPlain) < 17 {
		return nil, fmt.Errorf("login: rsa plaintext too short (%d bytes)", len(rsaPlain))
	}
	if rsaPlain[0] != 1 {
		return nil, fmt.Errorf("login: rsa plaintext missing 0x01 header (got 0x%02x)", rsaPlain[0])
	}
	return []uint32{
		binary.BigEndian.Uint32(rsaPlain[1:5]),
		binary.BigEndian.Uint32(rsaPlain[5:9]),
		binary.BigEndian.Uint32(rsaPlain[9:13]),
		binary.BigEndian.Uint32(rsaPlain[13:17]),
	}, nil
}

// ParseCapturedPlaintextFrame decodes a tools/agent [LOGIN-FRAME] dump into the
// fixed header, plaintext XTEA zone, and outer login type byte.
func ParseCapturedPlaintextFrame(raw []byte) (header []byte, plainZone []byte, loginType byte, err error) {
	frame, err := decodeCaptureInput(raw)
	if err != nil {
		return nil, nil, 0, err
	}
	return parseDecodedPlaintextFrame(frame)
}

func parseDecodedPlaintextFrame(frame []byte) (header []byte, plainZone []byte, loginType byte, err error) {
	if len(frame) < 3+loginBodyHead+2 {
		return nil, nil, 0, fmt.Errorf("login: capture frame too short (%d bytes)", len(frame))
	}
	loginType = frame[0]
	body := frame[3:]
	rsaLen := int(body[loginBodyHead])<<8 | int(body[loginBodyHead+1])
	zoneStart := loginBodyHead + 2 + rsaLen
	if zoneStart > len(body) {
		return nil, nil, 0, fmt.Errorf("login: capture rsaLen %d overruns body (%d bytes)", rsaLen, len(body))
	}
	return append([]byte(nil), body[:loginBodyHead]...), append([]byte(nil), body[zoneStart:]...), loginType, nil
}

func decodeCaptureInput(raw []byte) ([]byte, error) {
	if len(raw) >= 3 && (raw[0] == loginTypeNew || raw[0] == loginTypeReconn) {
		declLen := int(raw[1])<<8 | int(raw[2])
		if declLen > 0 && len(raw) >= 3+declLen {
			return raw, nil
		}
	}
	return decodeCaptureHex(raw)
}

func decodeCaptureHex(raw []byte) ([]byte, error) {
	s := strings.TrimSpace(string(raw))
	if i := strings.Index(strings.ToLower(s), "[login-frame]"); i >= 0 {
		s = strings.TrimSpace(s[i+len("[LOGIN-FRAME]"):])
	}
	s = strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			return r
		}
		return -1
	}, s)
	if s == "" {
		return nil, fmt.Errorf("login: no hex in capture file")
	}
	return hex.DecodeString(strings.ToLower(s))
}

// LoginFromCapture replays a captured plaintext login frame. It preserves the
// captured XTEA zone byte-for-byte (CRC order/endianness included), re-encrypts
// it with the captured ISAAC/XTEA seeds, and rebuilds only the RSA block with
// the live server seed from the current handshake.
func LoginFromCapture(conn net.Conn, captureFrame, rsaPlain []byte, rsaKey *RSAPublicKey, timeout time.Duration) (*LoginResult, error) {
	if rsaKey == nil {
		return nil, errors.New("login: no RSA public key configured")
	}
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
		defer conn.SetDeadline(time.Time{})
	}

	seeds, err := LoginSeedsFromRSAPlaintext(rsaPlain)
	if err != nil {
		return nil, err
	}

	serverSeed, err := loginHandshake(conn)
	if err != nil {
		return nil, err
	}

	frame, err := BuildWireFrameFromCapture(captureFrame, rsaPlain, rsaKey, serverSeed)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(frame); err != nil {
		return nil, fmt.Errorf("login: write capture replay: %w", err)
	}

	playerIndex, inCipher, outCipher, err := HandleLoginResponse(conn, seeds)
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		OutCipher:   outCipher,
		InCipher:    inCipher,
		PlayerIndex: playerIndex,
	}, nil
}

// BuildLoginPayload assembles the login body for diagnostics/tests.
func BuildLoginPayload(cfg LoginConfig, rsaKey *RSAPublicKey, serverSeed uint64) ([]byte, []uint32, error) {
	return buildLoginPayload(cfg, rsaKey, serverSeed)
}

// loginHandshake sends the game-login service byte and reads the server's
// session key. Returns the 8-byte server seed.
func loginHandshake(conn net.Conn) (uint64, error) {
	if _, err := conn.Write([]byte{serviceGameLogin}); err != nil {
		return 0, fmt.Errorf("login: write service byte: %w", err)
	}

	// Server replies with a status byte (0 = continue) followed by the 8-byte
	// server session key. Non-zero status is an early rejection.
	status := make([]byte, 1)
	if _, err := io.ReadFull(conn, status); err != nil {
		return 0, fmt.Errorf("login: read handshake status: %w", err)
	}
	if status[0] != 0 {
		return 0, loginError(status[0])
	}

	seedBuf := make([]byte, 8)
	if _, err := io.ReadFull(conn, seedBuf); err != nil {
		return 0, fmt.Errorf("login: read server seed: %w", err)
	}
	return binary.BigEndian.Uint64(seedBuf), nil
}

// buildLoginPayload assembles the login body that sits behind the outer
// login-type/uint16-length wrapper. It is a byte-exact translation of the
// decompiled client (cfr-out/client.java:2706-2839, xi.db at xi.java:932):
//
//	ld(revision) ld(1) ld(revision) bc(gd) bc(gy) bc(0)
//	<RSA block: bw(len)+ciphertext>
//	<XTEA zone: cc(user) bc(flags) bw(w) bw(h) platform(24) cc(token)
//	            ld(ub.gm) bc(0) machineInfo(55) bc(0) ld(0) CRCs(23)>
//
// The RSA plaintext and the CRC field order/endianness match the client exactly
// (see the helper comments). Only the XTEA zone (from the username onward) is
// XTEA-encrypted, mirroring xi.ds(...).
//
// It returns the assembled body and the four seed words so the caller can seed
// the ISAAC opcode ciphers (out = seeds, in = seeds+50).
func buildLoginPayload(cfg LoginConfig, rsaKey *RSAPublicKey, serverSeed uint64) ([]byte, []uint32, error) {
	// 1. Generate the four client key words (client's pi.lu.nextInt() x4).
	var seedBuf [16]byte
	if _, err := rand.Read(seedBuf[:]); err != nil {
		return nil, nil, fmt.Errorf("login: generate client seeds: %w", err)
	}
	seeds := []uint32{
		binary.BigEndian.Uint32(seedBuf[0:4]),
		binary.BigEndian.Uint32(seedBuf[4:8]),
		binary.BigEndian.Uint32(seedBuf[8:12]),
		binary.BigEndian.Uint32(seedBuf[12:16]),
	}

	// 2. Inner RSA block (client.java:2712-2757).
	// dt.ag() == 2 (ez.az), switch case 0 -> 4 reserved bytes, then credential:
	//   password login: bc(aao.ak.ag()==0) + cc(bn.bq password)
	//   Jagex token:    bc(aao.ag.ag()==2) + cc(var1_2.pk token)
	rsaBuffer := make([]byte, 0, 128)
	rsaBuffer = append(rsaBuffer, 1) // bc(1) RSA sync header
	rsaBuffer = appendU32(rsaBuffer, seeds[0])
	rsaBuffer = appendU32(rsaBuffer, seeds[1])
	rsaBuffer = appendU32(rsaBuffer, seeds[2])
	rsaBuffer = appendU32(rsaBuffer, seeds[3])
	rsaBuffer = appendU64(rsaBuffer, serverSeed) // fn(bj.lz)
	rsaBuffer = append(rsaBuffer, 2)             // bc(dt.ag()) auth type
	rsaBuffer = append(rsaBuffer, 0, 0, 0, 0)    // switch case 0: 4 reserved bytes

	rsaFlag := byte(0) // aao.ak.ag() password mode
	credential := cfg.Password
	if cfg.ClientToken != "" {
		rsaFlag = 2 // aao.ag.ag() Jagex launcher token mode
		credential = cfg.GameSessionToken
		if credential == "" {
			// Historical fallback for diagnostics; live Jagex-account logins should
			// set GameSessionToken to the freshly minted client.pk value.
			credential = cfg.ClientToken
		}
	}
	rsaBuffer = append(rsaBuffer, rsaFlag)
	rsaBuffer = appendCStr(rsaBuffer, credential)
	rsaCiphertext := rsaKey.Encrypt(rsaBuffer)

	// 3. Outbound frame content. The client's ay buffer is [bc(16)][bw(len)][content].
	// Login() writes bc(16) as loginType and bw(len) as the outer u16; payload is
	// only the content region starting at ld(238).
	finalPacket := make([]byte, 0, 512)
	finalPacket = appendU32(finalPacket, cfg.Revision) // ld(238)
	finalPacket = appendU32(finalPacket, 1)            // ld(1)
	finalPacket = appendU32(finalPacket, cfg.Revision) // ld(aac.ak) == revision on live rev 238
	// Live Jagex-account login (golden frame capture): gd=0x01, gy=0x05.
	finalPacket = append(finalPacket, defaultByte(cfg.ClientOption1, 0x01)) // bc(gd)
	finalPacket = append(finalPacket, defaultByte(cfg.ClientOption2, 0x05)) // bc(gy)
	finalPacket = append(finalPacket, 0)                                    // bc(0)
	finalPacket = append(finalPacket, byte(len(rsaCiphertext)>>8), byte(len(rsaCiphertext)))
	finalPacket = append(finalPacket, rsaCiphertext...)

	if cfg.RequireCapturedMachineInfo && len(cfg.MachineInfo) == 0 {
		return nil, nil, errors.New("login: RequireCapturedMachineInfo set but MachineInfo blob is empty — refusing golden fallback")
	}

	// 4. Secure XTEA zone (client.java:2782-2829). The encrypted region starts at
	// the username (var10_37) and runs to the end.
	xteaBuffer := buildXteaZone(cfg)
	finalPacket = append(finalPacket, xtea.EncryptBuffer(xteaBuffer, seeds)...)

	if len(finalPacket) > 0xFFFF {
		return nil, nil, fmt.Errorf("login: block too large (%d bytes)", len(finalPacket))
	}
	return finalPacket, seeds, nil
}

// buildXteaZone builds the plaintext secure zone (everything XTEA-encrypted by
// xi.ds): username, flags, window size, platform blob, launcher token, device
// id, machine-info blob, and the 23 cache CRCs.
func buildXteaZone(cfg LoginConfig) []byte {
	b := make([]byte, 0, 256)
	// Jagex-account logins authenticate via fr.gf (ClientToken); the username
	// field in the secure zone is empty (verified by golden frame capture).
	username := cfg.Username
	if cfg.ClientToken != "" {
		username = ""
	}
	b = appendCStr(b, username) // cc(username)
	// bc((el?1:0)<<1 | (gk?1:0)); both default false on a fresh fixed-mode login.
	b = append(b, cfg.AccountFlags)
	b = appendU16(b, defaultU16(cfg.WindowWidth, 765))  // bw(width)
	b = appendU16(b, defaultU16(cfg.WindowHeight, 503)) // bw(height)
	b = append(b, loginPlatformInfo(cfg.PlatformInfo)...)
	b = appendCStr(b, cfg.ClientToken) // cc(fr.gf)
	b = appendU32(b, cfg.DeviceID)     // ld(ub.gm)
	b = append(b, 0)                   // bc(0)
	if len(cfg.MachineInfo) != 0 {
		b = append(b, cfg.MachineInfo...)
	} else {
		b = append(b, buildMachineInfoBlob()...)
	}
	b = append(b, 0)    // bc(0)
	b = appendU32(b, 0) // ld(0)
	if cfg.UsePlainCRCs {
		for i := 0; i < 23; i++ {
			b = appendU32(b, atCRC(cfg.ArchiveCRCs, i))
		}
	} else {
		b = appendArchiveCRCs(b, cfg.ArchiveCRCs)
	}
	return b
}

// BuildPlaintextLoginFrame returns the full on-wire login frame
// ([type][u16 len][header][rsa][zone]) with the XTEA zone left UNENCRYPTED, so
// it can be diffed byte-for-byte against a client-side golden reference dumped
// inside xi.ds() before encryption (see tools/frida/login_dump.js). The RSA
// block is still real ciphertext and will differ per run; everything else is
// directly comparable.
func BuildPlaintextLoginFrame(cfg LoginConfig, rsaKey *RSAPublicKey, serverSeed uint64) ([]byte, error) {
	payload, _, err := buildLoginPayload(cfg, rsaKey, serverSeed)
	if err != nil {
		return nil, err
	}
	// buildLoginPayload encrypts the zone; rebuild the plaintext zone and splice
	// it back over the encrypted tail. The header + RSA block length is fixed by
	// the RSA ciphertext size, so locate the zone start from the RSA length field.
	const headFixed = 4 + 4 + 4 + 1 + 1 + 1 // rev, 1, sentinel, gd, gy, 0
	if len(payload) < headFixed+2 {
		return nil, fmt.Errorf("login: payload too short to splice (%d)", len(payload))
	}
	rsaLen := int(payload[headFixed])<<8 | int(payload[headFixed+1])
	zoneStart := headFixed + 2 + rsaLen
	if zoneStart > len(payload) {
		return nil, fmt.Errorf("login: rsa length %d exceeds payload", rsaLen)
	}
	plain := append(append([]byte(nil), payload[:zoneStart]...), buildXteaZone(cfg)...)

	loginType := byte(loginTypeNew)
	if cfg.Reconnecting {
		loginType = loginTypeReconn
	}
	frame := make([]byte, 0, 3+len(plain))
	frame = append(frame, loginType)
	frame = append(frame, byte(len(plain)>>8), byte(len(plain)))
	frame = append(frame, plain...)
	return frame, nil
}

// BuildWireLoginFrame returns the full on-wire login packet with XTEA-encrypted zone.
func BuildWireLoginFrame(cfg LoginConfig, rsaKey *RSAPublicKey, serverSeed uint64) ([]byte, error) {
	payload, _, err := buildLoginPayload(cfg, rsaKey, serverSeed)
	if err != nil {
		return nil, err
	}
	loginType := byte(loginTypeNew)
	if cfg.Reconnecting {
		loginType = loginTypeReconn
	}
	frame := make([]byte, 0, 3+len(payload))
	frame = append(frame, loginType)
	frame = append(frame, byte(len(payload)>>8), byte(len(payload)))
	frame = append(frame, payload...)
	return frame, nil
}

// CRC int-encoding selectors, matching the client's four writeInt variants:
// ld=big-endian, ee=little-endian, bq=middle-endian, ea=inverse-middle-endian.
const (
	encBE = iota
	encLE
	encME
	encIME
)

// archiveCRCField pairs a cache-archive index (into LoginConfig.ArchiveCRCs)
// with the byte order the client uses for it.
type archiveCRCField struct {
	idx int
	enc int
}

// archiveCRCOrder is the CRC write sequence for revision 239, reverse-engineered
// from a live RuneLite golden capture (tools/cmd/crcprobe). Each entry maps a
// cache-archive index to one of the client's four int byte orders (ld/ee/bq/ea).
// Index 16 is always CRC 0 (empty archive). Do not reuse the rev-238 order here.
var archiveCRCOrder = []archiveCRCField{
	{18, encME}, {19, encME}, {22, encBE}, {12, encLE}, {9, encLE}, {1, encME},
	{17, encME}, {16, encBE}, {7, encIME}, {13, encLE}, {3, encBE}, {5, encME},
	{10, encIME}, {11, encBE}, {2, encME}, {8, encLE}, {0, encIME}, {21, encBE},
	{4, encIME}, {20, encME}, {6, encLE}, {14, encIME}, {15, encLE},
}

// atCRC returns crcs[i] or 0 when out of range.
func atCRC(crcs []uint32, i int) uint32 {
	if i >= 0 && i < len(crcs) {
		return crcs[i]
	}
	return 0
}

// appendArchiveCRCs writes the cache CRCs in the client's scrambled order and
// per-field endianness. Missing indices default to 0.
func appendArchiveCRCs(b []byte, crcs []uint32) []byte {
	for _, f := range archiveCRCOrder {
		b = appendU32Enc(b, atCRC(crcs, f.idx), f.enc)
	}
	return b
}

// appendU32Enc writes v in one of the four RuneScape int byte orders.
func appendU32Enc(b []byte, v uint32, enc int) []byte {
	switch enc {
	case encLE:
		return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	case encME:
		return append(b, byte(v>>8), byte(v), byte(v>>24), byte(v>>16))
	case encIME:
		return append(b, byte(v>>16), byte(v>>24), byte(v), byte(v>>8))
	default: // encBE
		return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// Machine-info numeric header values, decoded byte-for-byte from a live RuneLite
// login captured before xi.ds() (tools/agent). The server accepted this exact
// blob, so we reproduce it rather than guessing telemetry shapes.
const (
	miVersion    = 9   // bc(9) machine-info format version
	miOSWindows  = 1   // operating system: 1=Windows, 2=mac, 3=linux
	miArch64     = 1   // 64-bit JVM
	miOSVersion  = 12  // Windows version code reported by RuneLite's JRE 11
	miJavaVendor = 2   // JVM vendor code
	miJavaMajor  = 11  // RuneLite ships a JRE 11 (NOT 17)
	miJavaMinor  = 0   //
	miJavaPatch  = 30  // 11.0.30
	miReserved   = 0   // single reserved byte between version and max-memory
	miMaxMemMB   = 769 // -Xmx768m rounded to the client's MB report
	miProcessors = 16  // logical CPUs
)

// machineInfoHeaderLen is the length of the numeric header reproduced by
// buildMachineInfoBlob before the opaque launch-telemetry tail begins.
const machineInfoHeaderLen = 13

// goldenMachineInfo is the full machine-info blob captured verbatim from a live
// RuneLite 1.12.28 (JRE 11) login on 2026-06-06 (tools/cmd/framedump output).
// The tail after the numeric header carries RuneLite's launch metadata — the
// "java.exe" executable name, the obfuscated class-path/main-class command, and
// the "-javaagent" jar — which is environment-specific and opaque to us. We
// replay it because the live login server validated this frame. buildMachineInfoBlob
// rebuilds the numeric header from named constants and appends this captured tail;
// TestMachineInfoMatchesGolden asserts the result is byte-identical.
var goldenMachineInfo = []byte{
	0x09, 0x01, 0x01, 0x00, 0x0c, 0x02, 0x0b, 0x00, 0x1e, 0x00, 0x03, 0x01,
	0x10, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6a,
	0x61, 0x76, 0x61, 0x2e, 0x65, 0x78, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x34, 0x32, 0x36, 0x2b, 0x38, 0x38, 0x34, 0x2b, 0x63, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x34, 0x31, 0x32, 0x32, 0x79, 0x71, 0x0a, 0x63, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x31, 0x39, 0x35, 0x33, 0x37, 0x71, 0x6a, 0x0a, 0x6e,
	0x72, 0x63, 0x2e, 0x52, 0x75, 0x6e, 0x65, 0x4c, 0x69, 0x74, 0x65, 0x32,
	0x39, 0x37, 0x73, 0x74, 0x61, 0x72, 0x74, 0x0a, 0x6e, 0x72, 0x63, 0x2e,
	0x52, 0x75, 0x6e, 0x65, 0x4c, 0x69, 0x74, 0x65, 0x32, 0x37, 0x34, 0x6d,
	0x61, 0x69, 0x6e, 0x0a, 0x00, 0x00, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x2d,
	0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x6a, 0x61, 0x72, 0x00,
}

// buildMachineInfoBlob serializes the client's kg.ps/vu machine-info block to
// match the captured golden frame exactly: a numeric header (version, OS, JVM,
// memory, CPUs) built from named constants, followed by RuneLite's opaque launch
// telemetry tail (goldenMachineInfo beyond the header). The numeric header is
// fixed to the captured RuneLite/JRE-11 environment so the frame stays
// byte-identical to a frame the live server already accepted.
func buildMachineInfoBlob() []byte {
	b := make([]byte, 0, len(goldenMachineInfo))
	b = append(b, miVersion)      // bc(9) version
	b = append(b, miOSWindows)    // operating system
	b = append(b, miArch64)       // 64-bit flag
	b = appendU16(b, miOSVersion) // OS version code
	b = append(b, miJavaVendor)   // JVM vendor
	b = append(b, miJavaMajor)    // java version major (11)
	b = append(b, miJavaMinor)    // java version minor
	b = append(b, miJavaPatch)    // java version patch (.30)
	b = append(b, miReserved)     // reserved byte
	b = appendU16(b, miMaxMemMB)  // max heap MB (-Xmx768m)
	b = append(b, miProcessors)   // available processors
	// Append RuneLite's captured launch-telemetry tail (java.exe, command, agent).
	b = append(b, goldenMachineInfo[machineInfoHeaderLen:]...)
	return b
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendU64(b []byte, v uint64) []byte {
	return append(b,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// appendCStr appends a null-terminated string (the classic RuneScape string
// framing used in the login block).
func appendCStr(b []byte, s string) []byte {
	b = append(b, []byte(s)...)
	return append(b, 0)
}

func defaultU16(v, fallback uint16) uint16 {
	if v == 0 {
		return fallback
	}
	return v
}

func defaultByte(v, fallback byte) byte {
	if v == 0 {
		return fallback
	}
	return v
}

func loginPlatformInfo(v []byte) []byte {
	if len(v) != 0 {
		return v
	}
	// qm.hh(...) falls back to bv.ae(), which returns a 24-byte machine-id blob.
	// When random.dat is unavailable/empty the client fills the blob with -1.
	const platformInfoLen = 24
	out := make([]byte, platformInfoLen)
	for i := range out {
		out[i] = 0xff
	}
	return out
}
