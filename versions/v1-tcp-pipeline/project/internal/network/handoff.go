package network

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const handoffMaxBytes = 2 << 20 // 2 MiB

// SessionHandoff is the live host→container login state bundle pushed over TCP
// immediately after wire-block capture. It replaces .env/file polling for the
// critical pk + machine-info window.
type SessionHandoff struct {
	Version          int    `json:"v"`
	GameSessionToken string `json:"gameSessionToken"`
	ClientToken      string `json:"clientToken"`
	MachineInfoHex   string `json:"machineInfoHex,omitempty"`
	PlatformInfoHex  string `json:"platformInfoHex,omitempty"`
	RSAPlaintextHex  string `json:"rsaPlaintextHex,omitempty"`
	LoginFrameHex    string `json:"loginFrameHex,omitempty"`
	WireBlocked      bool   `json:"wireBlocked"`
	CapturedAt       string `json:"capturedAt,omitempty"`
}

// WaitForHandoff listens on addr (e.g. ":17494") until one JSON handoff arrives
// or ctx/timeout elapses. The caller should start the listener before launching
// RuneLite so the JVM agent can push as soon as wire-block completes.
func WaitForHandoff(ctx context.Context, addr string, timeout time.Duration) (*SessionHandoff, error) {
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(timeout)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("handoff: listen %s: %w", addr, err)
	}
	defer ln.Close()

	waitCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	type acceptResult struct {
		h   *SessionHandoff
		err error
	}
	ch := make(chan acceptResult, 1)
	go func() {
		h, err := acceptOneHandoff(ln, waitCtx)
		ch <- acceptResult{h, err}
	}()

	select {
	case <-waitCtx.Done():
		return nil, fmt.Errorf("handoff: timeout waiting on %s: %w", addr, waitCtx.Err())
	case r := <-ch:
		return r.h, r.err
	}
}

func acceptOneHandoff(ln net.Listener, ctx context.Context) (*SessionHandoff, error) {
	for {
		conn, err := acceptWithContext(ln, ctx)
		if err != nil {
			return nil, err
		}
		h, err := readHandoff(conn)
		_ = conn.Close()
		if err == nil {
			return h, nil
		}
		// Bad payload — keep listening until ctx expires.
	}
}

func acceptWithContext(ln net.Listener, ctx context.Context) (net.Conn, error) {
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.c, r.err
	}
}

func readHandoff(conn net.Conn) (*SessionHandoff, error) {
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReader(io.LimitReader(conn, handoffMaxBytes))
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("handoff: read: %w", err)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, errors.New("handoff: empty payload")
	}
	var h SessionHandoff
	if err := json.Unmarshal([]byte(line), &h); err != nil {
		return nil, fmt.Errorf("handoff: json: %w", err)
	}
	if err := h.Validate(); err != nil {
		return nil, err
	}
	return &h, nil
}

// Validate checks required fields for an immediate capture replay login.
func (h *SessionHandoff) Validate() error {
	if h == nil {
		return errors.New("handoff: nil")
	}
	if h.Version == 0 {
		h.Version = 1
	}
	if h.GameSessionToken == "" {
		return errors.New("handoff: gameSessionToken required")
	}
	if h.ClientToken == "" {
		return errors.New("handoff: clientToken required")
	}
	if h.LoginFrameHex == "" {
		return errors.New("handoff: loginFrameHex required")
	}
	if h.RSAPlaintextHex == "" {
		return errors.New("handoff: rsaPlaintextHex required")
	}
	if !h.WireBlocked {
		return errors.New("handoff: wireBlocked must be true (pk would be burned)")
	}
	return nil
}

// ApplyToLoginConfig copies handoff blobs into cfg and enables capture replay.
func (h *SessionHandoff) ApplyToLoginConfig(cfg *LoginConfig) error {
	if err := h.Validate(); err != nil {
		return err
	}
	cfg.GameSessionToken = h.GameSessionToken
	cfg.ClientToken = h.ClientToken
	cfg.RequireCapturedMachineInfo = true

	if h.MachineInfoHex != "" {
		mi, err := decodeHexField("machineInfoHex", h.MachineInfoHex)
		if err != nil {
			return err
		}
		cfg.MachineInfo = mi
	}
	if h.PlatformInfoHex != "" {
		pi, err := decodeHexField("platformInfoHex", h.PlatformInfoHex)
		if err != nil {
			return err
		}
		if len(pi) != 24 {
			return fmt.Errorf("handoff: platformInfoHex must be 24 bytes, got %d", len(pi))
		}
		cfg.PlatformInfo = pi
	}

	frame, err := decodeHexField("loginFrameHex", h.LoginFrameHex)
	if err != nil {
		return err
	}
	rsaPlain, err := decodeHexField("rsaPlaintextHex", h.RSAPlaintextHex)
	if err != nil {
		return err
	}
	cfg.CaptureFrame = frame
	cfg.CaptureRSAPlain = rsaPlain

	if len(cfg.MachineInfo) == 0 || len(cfg.PlatformInfo) == 0 {
		mi, pi, err := extractBlobHexFromFrame(frame)
		if err != nil {
			return err
		}
		if len(cfg.MachineInfo) == 0 {
			cfg.MachineInfo = mi
		}
		if len(cfg.PlatformInfo) == 0 {
			cfg.PlatformInfo = pi
		}
	}
	if len(cfg.MachineInfo) == 0 {
		return errors.New("handoff: machine-info blob missing")
	}
	if len(cfg.PlatformInfo) != 24 {
		return errors.New("handoff: platform-info blob missing or wrong length")
	}
	return nil
}

func decodeHexField(name, s string) ([]byte, error) {
	s = strings.Map(hexCharLogin, strings.TrimSpace(s))
	if s == "" {
		return nil, fmt.Errorf("handoff: %s empty", name)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("handoff: %s: %w", name, err)
	}
	return b, nil
}

func hexCharLogin(r rune) rune {
	if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
		return r
	}
	return -1
}

// extractBlobHexFromFrame pulls platform + machine-info from a plaintext capture frame.
func extractBlobHexFromFrame(frame []byte) (machineInfo, platformInfo []byte, err error) {
	_, zone, _, err := ParseCapturedPlaintextFrame(frame)
	if err != nil {
		return nil, nil, err
	}
	z := 0
	_, z = readCStr(zone, z)
	if z+1+4 > len(zone) {
		return nil, nil, errors.New("handoff: truncated xtea zone")
	}
	z++ // flags
	z += 4 // window
	if z+24 > len(zone) {
		return nil, nil, errors.New("handoff: truncated platform info")
	}
	platformInfo = append([]byte(nil), zone[z:z+24]...)
	z += 24
	_, z = readCStr(zone, z)
	if z+5 > len(zone) {
		return nil, nil, errors.New("handoff: truncated post-token zone")
	}
	z += 5 // deviceID + bc(0)
	tail := 1 + 4 + 23*4
	miEnd := len(zone) - tail
	if miEnd <= z {
		return nil, nil, errors.New("handoff: machine-info region empty")
	}
	machineInfo = append([]byte(nil), zone[z:miEnd]...)
	return machineInfo, platformInfo, nil
}

func readCStr(b []byte, o int) (string, int) {
	start := o
	for o < len(b) && b[o] != 0 {
		o++
	}
	if o >= len(b) {
		return string(b[start:]), len(b)
	}
	return string(b[start:o]), o + 1
}
