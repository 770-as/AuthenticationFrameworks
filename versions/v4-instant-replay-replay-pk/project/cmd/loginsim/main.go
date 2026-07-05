// Command loginsim walks through the full game-login pipeline step by step,
// simulating what the bot does on connect. Use it after a Jagex client update
// to discover the live revision, refresh CRCs, and pinpoint which login layer
// is failing before editing internal/network/login.go.
//
//	go run ./cmd/loginsim
//	go run ./cmd/loginsim -mint                        # just-in-time pk mint (fixes code 10 from pk expiry)
//	go run ./cmd/loginsim -no-proxy -replay-capture   # clean-slate test (direct IP)
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"packet-bot/internal/config"
	"packet-bot/internal/network"
)

func main() {
	probeRev := false
	replayCapture := false
	mintReplay := false
	loginOnly := false
	noProxy := false
	jitMint := false
	captureFile := ""
	credsFile := ""
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-probe-revision", "--probe-revision":
			probeRev = true
		case "-replay-capture", "--replay-capture":
			replayCapture = true
		case "-mint-replay", "--mint-replay":
			mintReplay = true
			replayCapture = true
		case "-login-only", "--login-only":
			loginOnly = true
		case "-no-proxy", "--no-proxy":
			noProxy = true
		case "-mint", "--mint":
			jitMint = true
		case "-capture-file", "--capture-file":
			if i+1 < len(args) {
				captureFile = args[i+1]
				i++
			}
		case "-credentials", "--credentials":
			if i+1 < len(args) {
				credsFile = args[i+1]
				i++
			}
		}
	}
	if captureFile == "" {
		home, _ := os.UserHomeDir()
		captureFile = filepath.Join(home, "login_frame.txt")
	}

	if err := loadDotEnv(".env"); err != nil {
		fmt.Printf("warning: could not load .env: %v\n", err)
	}

	env := config.FromEnv()
	if noProxy {
		env.ProxyURL = ""
	}
	if env.ServerAddr == "" {
		fmt.Println("SERVER_ADDR not set; aborting")
		os.Exit(1)
	}

	timeout := 15 * time.Second
	fmt.Println("=== OSRS Login Flow Simulation ===")
	fmt.Printf("target: %s\n", env.ServerAddr)
	if env.ProxyURL != "" {
		fmt.Printf("proxy:  %s\n", config.MaskProxyURL(env.ProxyURL))
	} else {
		fmt.Println("proxy:  (none — direct connect)")
	}
	fmt.Println()

	rev := env.Revision
	if rev == 0 {
		rev = 239
	}

	if loginOnly {
		if !replayCapture {
			fmt.Println("-login-only requires -replay-capture or -mint-replay")
			os.Exit(1)
		}
		fmt.Println("[login-only] skipping JS5/CRC/frame diagnostics (pk is short-lived)")
		fmt.Println()
		if mintReplay {
			runMintReplayLogin(env, rev, captureFile, credsFile, timeout)
		} else {
			runCaptureLogin(env, rev, captureFile, timeout)
		}
		return
	}

	// --- Step 1: discover live revision ---
	fmt.Printf("[1/6] JS5 revision check (configured=%d)\n", rev)
	ok, err := js5Accepts(env, rev, timeout)
	if err != nil {
		fmt.Printf("      dial/handshake error: %v\n", err)
		os.Exit(1)
	}
	if !ok {
		fmt.Printf("      revision %d rejected (status 6 = out of date)\n", rev)
		if probeRev || rev != 0 {
			fmt.Println("      scanning revisions 230-250...")
			found := uint32(0)
			for r := uint32(230); r <= 250; r++ {
				accept, _ := js5Accepts(env, r, timeout)
				if accept {
					found = r
					break
				}
			}
			if found == 0 {
				fmt.Println("      no accepted revision in range 230-250")
				os.Exit(1)
			}
			fmt.Printf("      >>> live revision appears to be %d (update CLIENT_REVISION)\n", found)
			rev = found
		} else {
			fmt.Println("      re-run with -probe-revision to auto-scan")
			os.Exit(1)
		}
	} else {
		fmt.Printf("      revision %d accepted by JS5 handshake\n", rev)
	}
	fmt.Println()

	// --- Step 2: fetch cache CRCs ---
	fmt.Printf("[2/6] JS5 master index CRC table (rev %d)\n", rev)
	crcs, err := fetchCRCs(env, rev, timeout)
	if err != nil {
		fmt.Printf("      fetch failed: %v\n", err)
	} else {
		fmt.Printf("      fetched %d index CRCs\n", len(crcs))
		if !crcSliceEqual(crcs, env.ArchiveCRCs) {
			fmt.Println("      >>> CLIENT_ARCHIVE_CRCS in .env is STALE")
			fmt.Printf("      CLIENT_ARCHIVE_CRCS=%s\n", joinCRCs(crcs))
		} else {
			fmt.Println("      CRCs match .env")
		}
	}
	fmt.Println()

	// --- Step 3: RSA key ---
	fmt.Printf("[3/6] RSA public key\n")
	if env.RSAModulus == "" {
		fmt.Println("      RSA_MODULUS not set — login will fail")
		os.Exit(1)
	}
	rsaKey, err := network.NewRSAPublicKey(env.RSAModulus, env.RSAExponent)
	if err != nil || rsaKey == nil {
		fmt.Printf("      invalid RSA key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("      modulus loaded (%d bits)\n", rsaKey.Modulus.BitLen())
	fmt.Println()

	// --- Step 4: session credentials ---
	fmt.Printf("[4/6] session credentials\n")
	fmt.Printf("      account: %s\n", config.MaskSecret(env.AccountUser))
	if env.ClientToken != "" {
		fmt.Printf("      CLIENT_TOKEN (fr.gf): set, len=%d (session-bound; re-capture if stale)\n", len(env.ClientToken))
	} else {
		fmt.Println("      CLIENT_TOKEN: empty (password login mode)")
	}
	if env.GameSessionToken != "" {
		fmt.Printf("      GAME_SESSION_TOKEN (client.pk): set, len=%d (mint before login)\n", len(env.GameSessionToken))
	} else if env.ClientToken != "" {
		fmt.Println("      GAME_SESSION_TOKEN: MISSING — Jagex logins need client.pk in RSA block")
	}
	fmt.Println()

	// --- Step 5: build login frame ---
	fmt.Printf("[5/6] build login frame (rev %d)\n", rev)
	cfg := loginConfigFromEnv(env, rsaKey, rev, crcs)
	if jitMint && !replayCapture {
		credPath := credsFile
		if credPath == "" {
			credPath = network.DefaultCredentialsPath()
		}
		mintProxy := env.ProxyURL
		mintTimeout := timeout
		cfg.PKMinter = func() (string, error) {
			sessionID, characterID, err := network.ReadJXCredentials(credPath)
			if err != nil {
				return "", err
			}
			res, err := network.MintGameSessionTokenWithMeta(
				network.DefaultGameSessionEndpoint, sessionID, characterID, mintProxy, mintTimeout)
			if err != nil {
				return "", err
			}
			if mintProxy != "" {
				fmt.Printf("      minted pk len=%d prefix=%s... via PROXY (same egress as game login)\n",
					len(res.Token), prefixToken(res.Token, 6))
			} else {
				fmt.Printf("      minted pk len=%d prefix=%s... via direct\n",
					len(res.Token), prefixToken(res.Token, 6))
			}
			return res.Token, nil
		}
		fmt.Printf("      JIT mint ENABLED: pk minted fresh from %s just before the login write\n", credPath)
	} else if jitMint && replayCapture {
		fmt.Println("      note: -mint ignored in -replay-capture mode (replay uses captured RSA plaintext)")
	}
	plain, err := network.BuildPlaintextLoginFrame(cfg, rsaKey, 0)
	if err != nil {
		fmt.Printf("      build failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("      plaintext frame: %d bytes\n", len(plain))
	fmt.Printf("      header: rev=%d gd=0x%02x gy=0x%02x\n", rev, cfg.ClientOption1, cfg.ClientOption2)
	if cfg.ClientOption1 == 0 {
		fmt.Println("      gd/gy using defaults 0x01/0x05 (verify against golden capture if login fails)")
	}
	fmt.Printf("      XTEA zone would be %d bytes after RSA block\n", len(plain)-frameZoneStart(plain))
	fmt.Println("      run: go run ./cmd/logindiff -mine   (our frame hex)")
	fmt.Println("      run: go run ./cmd/logindiff -file login_frame.txt  (diff vs RuneLite capture)")
	fmt.Println()

	// --- Step 6: live login attempt ---
	fmt.Printf("[6/6] live login attempt")
	if replayCapture {
		fmt.Printf(" (capture replay from %s)", captureFile)
	}
	fmt.Println()
	if replayCapture {
		runCaptureLogin(env, rev, captureFile, timeout)
		return
	}
	conn, err := dial(env, timeout)
	if err != nil {
		fmt.Printf("      connect failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	res, err := network.Login(conn, cfg)
	if err != nil {
		fmt.Printf("      LOGIN RESULT: %v\n", err)
		fmt.Println()
		printDiagnosis(err.Error(), env)
		os.Exit(1)
	}
	fmt.Printf("      LOGIN RESULT: success, player index %d\n", res.PlayerIndex)
	fmt.Println()
	fmt.Println("=== Simulation complete: login accepted ===")
}

func runCaptureLogin(env config.Config, rev uint32, captureFile string, timeout time.Duration) {
	rsaKey, err := network.NewRSAPublicKey(env.RSAModulus, env.RSAExponent)
	if err != nil || rsaKey == nil {
		fmt.Printf("      invalid RSA key: %v\n", err)
		os.Exit(1)
	}
	cfg := loginConfigFromEnv(env, rsaKey, rev, nil)

	conn, err := dial(env, timeout)
	if err != nil {
		fmt.Printf("      connect failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	captureBytes, rerr := os.ReadFile(captureFile)
	if rerr != nil {
		fmt.Printf("      read capture: %v\n", rerr)
		os.Exit(1)
	}
	rsaPlain, rerr := loadRSAPlaintext(env)
	if rerr != nil {
		fmt.Printf("      rsa plaintext: %v\n", rerr)
		os.Exit(1)
	}
	res, err := network.LoginFromCapture(conn, captureBytes, rsaPlain, rsaKey, cfg.Timeout)
	if err != nil {
		fmt.Printf("      LOGIN RESULT: %v\n", err)
		fmt.Println()
		printDiagnosis(err.Error(), env)
		os.Exit(1)
	}
	fmt.Printf("      LOGIN RESULT: success, player index %d\n", res.PlayerIndex)
	fmt.Println()
	fmt.Println("=== Simulation complete: login accepted ===")
}

func runMintReplayLogin(env config.Config, rev uint32, captureFile, credsFile string, timeout time.Duration) {
	rsaKey, err := network.NewRSAPublicKey(env.RSAModulus, env.RSAExponent)
	if err != nil || rsaKey == nil {
		fmt.Printf("      invalid RSA key: %v\n", err)
		os.Exit(1)
	}
	cfg := loginConfigFromEnv(env, rsaKey, rev, nil)

	credPath := credsFile
	if credPath == "" {
		credPath = network.DefaultCredentialsPath()
	}
	sessionID, characterID, err := network.ReadJXCredentials(credPath)
	if err != nil {
		fmt.Printf("      read JX credentials: %v\n", err)
		os.Exit(1)
	}
	mintProxy := env.ProxyURL
	pk, err := network.MintGameSessionToken("", sessionID, characterID, mintProxy, timeout)
	if err != nil {
		fmt.Printf("      mint pk: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("      minted fresh pk len=%d prefix=%s...\n", len(pk), prefixToken(pk, 6))

	rsaPlain, err := loadRSAPlaintext(env)
	if err != nil {
		fmt.Printf("      rsa plaintext: %v\n", err)
		os.Exit(1)
	}
	patchedRSA, err := network.PatchRSAPlaintextGameSessionToken(rsaPlain, pk)
	if err != nil {
		fmt.Printf("      patch rsa pk: %v\n", err)
		os.Exit(1)
	}

	captureBytes, err := os.ReadFile(captureFile)
	if err != nil {
		fmt.Printf("      read capture: %v\n", err)
		os.Exit(1)
	}

	conn, err := dial(env, timeout)
	if err != nil {
		fmt.Printf("      connect failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	res, err := network.LoginFromCapture(conn, captureBytes, patchedRSA, rsaKey, cfg.Timeout)
	if err != nil {
		fmt.Printf("      LOGIN RESULT: %v\n", err)
		fmt.Println()
		printDiagnosis(err.Error(), env)
		os.Exit(1)
	}
	fmt.Printf("      LOGIN RESULT: success, player index %d\n", res.PlayerIndex)
	fmt.Println()
	fmt.Println("=== Simulation complete: login accepted (mint-replay) ===")
}

func loginConfigFromEnv(env config.Config, rsaKey *network.RSAPublicKey, rev uint32, crcs []uint32) network.LoginConfig {
	useCRCs := env.ArchiveCRCs
	if len(crcs) > 0 {
		useCRCs = crcs
	}
	cfg := network.LoginConfig{
		Username:         env.AccountUser,
		Password:         env.AccountPass,
		Revision:         rev,
		RSA:              rsaKey,
		ArchiveCRCs:      useCRCs,
		ClientToken:      env.ClientToken,
		GameSessionToken: env.GameSessionToken,
		Timeout:          15 * time.Second,
	}
	if env.MachineInfoHex != "" {
		if mi, err := hex.DecodeString(strings.TrimSpace(env.MachineInfoHex)); err == nil {
			cfg.MachineInfo = mi
		}
	}
	if env.PlatformInfoHex != "" {
		if pi, err := hex.DecodeString(strings.TrimSpace(env.PlatformInfoHex)); err == nil && len(pi) == 24 {
			cfg.PlatformInfo = pi
		}
	}
	if v := os.Getenv("DEVICE_ID"); v != "" {
		if id, err := strconv.ParseUint(v, 10, 32); err == nil {
			cfg.DeviceID = uint32(id)
		}
	}
	return cfg
}

func js5Accepts(env config.Config, rev uint32, timeout time.Duration) (bool, error) {
	conn, err := dial(env, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	h := network.NewHandshakeHandler(conn)
	if err := h.SendVerification(rev); err != nil {
		if strings.Contains(err.Error(), "Status 6") || strings.Contains(err.Error(), "out of date") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func fetchCRCs(env config.Config, rev uint32, timeout time.Duration) ([]uint32, error) {
	conn, err := dial(env, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	h := network.NewHandshakeHandler(conn)
	if err := h.SendVerification(rev); err != nil {
		return nil, err
	}

	req := []byte{1, 255, byte(255 >> 8), byte(255)}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	for len(buf) < 600 {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	if len(buf) < 8 {
		return nil, fmt.Errorf("checksum table response too short (%d bytes)", len(buf))
	}
	length := int(buf[4])<<24 | int(buf[5])<<16 | int(buf[6])<<8 | int(buf[7])
	data := buf[8:]
	if len(data) > length {
		data = data[:length]
	}
	n := len(data) / 8
	out := make([]uint32, n)
	for i := 0; i < n; i++ {
		off := i * 8
		out[i] = binary.BigEndian.Uint32(data[off : off+4])
	}
	return out, nil
}

func dial(env config.Config, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if env.ProxyURL != "" {
		d, err := network.NewDialer(env.ProxyURL, timeout)
		if err != nil {
			return nil, err
		}
		return d.DialContext(ctx, "tcp", env.ServerAddr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", env.ServerAddr)
}

func frameZoneStart(frame []byte) int {
	const headFixed = 15
	if len(frame) < headFixed+2 {
		return len(frame)
	}
	rsaLen := int(frame[headFixed])<<8 | int(frame[headFixed+1])
	return headFixed + 2 + rsaLen
}

func crcSliceEqual(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func joinCRCs(crcs []uint32) string {
	parts := make([]string, len(crcs))
	for i, c := range crcs {
		parts[i] = strconv.FormatUint(uint64(c), 10)
	}
	return strings.Join(parts, ",")
}

func printDiagnosis(errMsg string, env config.Config) {
	fmt.Println("--- Diagnosis ---")
	switch {
	case strings.Contains(errMsg, "code 6"):
		fmt.Println("Revision or CRCs are wrong. Re-run with -probe-revision and update CLIENT_REVISION + CLIENT_ARCHIVE_CRCS.")
	case strings.Contains(errMsg, "code 10"):
		fmt.Println("Bad session id — the pk (GAME_SESSION_TOKEN) was rejected. It is short-lived.")
		fmt.Println("  Wire-block: captured pk cannot be replayed; use -mint-replay (fresh pk + captured XTEA zone).")
		fmt.Println("  capture-netns: use -no-proxy (-ViaNetgate) so mint + game login match RuneLite egress.")
		fmt.Println("  Re-capture with -InstantReplay if JX credentials expired or pk sat idle >30s.")
		fmt.Println("  go run ./cmd/logindiff -file login_frame.txt  (verify frame matches)")
	case strings.Contains(errMsg, "code 63"):
		fmt.Println("Invalid/expired Jagex session token — re-mint GAME_SESSION_TOKEN.")
	case strings.Contains(errMsg, "code 3"):
		fmt.Println("Credentials rejected — check account/password or token pair.")
	case strings.Contains(errMsg, "code 22"):
		fmt.Println("Malformed login packet — login frame structure changed; decompile new client and diff with logindiff.")
	default:
		fmt.Println("See internal/network/login.go loginError() for response code meanings.")
	}
	if env.ClientToken == "" && env.GameSessionToken == "" && env.AccountPass != "" {
		fmt.Println("Tip: password-only login may no longer be supported; capture Jagex tokens from RuneLite.")
	}
	fmt.Println()
	fmt.Println("Rebuild checklist after client update:")
	fmt.Println("  • CLIENT_REVISION (JS5 probe)")
	fmt.Println("  • CLIENT_ARCHIVE_CRCS (step 2 of this tool)")
	fmt.Println("  • RSA_MODULUS (extract from injected client class bu, if changed)")
	fmt.Println("  • CLIENT_TOKEN + GAME_SESSION_TOKEN (fresh capture)")
	fmt.Println("  • archiveCRCOrder in login.go (if logindiff shows CRC zone mismatch)")
	fmt.Println("  • golden machine-info blob (if logindiff shows machine-info mismatch)")
}

func prefixToken(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func loadRSAPlaintext(_ config.Config) ([]byte, error) {
	if raw, err := os.ReadFile(filepath.Join(mustHome(), "rsa_plaintext.txt")); err == nil {
		if b, derr := decodeRSAPlaintextFile(raw); derr == nil {
			return b, nil
		}
	}
	hexStr := strings.TrimSpace(os.Getenv("RSA_PLAINTEXT_HEX"))
	if hexStr == "" {
		return nil, fmt.Errorf("RSA plaintext missing — capture with login agent (rsa_plaintext.txt or RSA_PLAINTEXT_HEX)")
	}
	return hex.DecodeString(strings.Map(hexChar, hexStr))
}

func mustHome() string {
	home, _ := os.UserHomeDir()
	if home == "" {
		return "."
	}
	return home
}

func decodeRSAPlaintextFile(raw []byte) ([]byte, error) {
	s := strings.TrimSpace(string(raw))
	if i := strings.Index(strings.ToLower(s), "[rsa-plaintext]"); i >= 0 {
		s = strings.TrimSpace(s[i+len("[RSA-PLAINTEXT]"):])
	}
	s = strings.Map(hexChar, s)
	if s == "" {
		return nil, fmt.Errorf("no hex in rsa plaintext file")
	}
	return hex.DecodeString(strings.ToLower(s))
}

func hexChar(r rune) rune {
	if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
		return r
	}
	return -1
}

func loadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, val)
		}
	}
	return sc.Err()
}

// silence unused import if build tags change
var _ = io.EOF
