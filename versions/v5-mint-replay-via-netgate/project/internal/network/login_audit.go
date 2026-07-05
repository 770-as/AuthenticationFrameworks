package network

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"packet-bot/internal/crypto/xtea"
)

// AuditLoginPayload compares raw binary buffers in 16-byte hex rows and prints
// each mismatched offset. Used to isolate structure drift between a captured
// client frame and the Go builder / replay output.
func AuditLoginPayload(golden, generated []byte) {
	fmt.Printf("=== LOGIN PAYLOAD AUDIT ===\n")
	fmt.Printf("Golden Len: %d | Generated Len: %d\n\n", len(golden), len(generated))

	maxLen := len(golden)
	if len(generated) > maxLen {
		maxLen = len(generated)
	}

	mismatches := 0
	for i := 0; i < maxLen; i += 16 {
		end := i + 16

		gHex := ""
		if i < len(golden) {
			gEnd := end
			if gEnd > len(golden) {
				gEnd = len(golden)
			}
			gHex = hex.EncodeToString(golden[i:gEnd])
		}

		genHex := ""
		if i < len(generated) {
			genEnd := end
			if genEnd > len(generated) {
				genEnd = len(generated)
			}
			genHex = hex.EncodeToString(generated[i:genEnd])
		}

		if gHex != genHex {
			mismatches++
			fmt.Printf("[MISMATCH] Offset 0x%04X (%d):\n", i, i)
			fmt.Printf("  Gold: %-32s\n", gHex)
			fmt.Printf("  Ours: %-32s\n", genHex)
		}
	}
	if mismatches == 0 {
		fmt.Println("[OK] payloads are byte-identical")
	} else {
		fmt.Printf("\nTotal mismatched 16-byte rows: %d\n", mismatches)
	}
}

// ServerSeedFromRSAPlaintext reads the 8-byte server seed embedded in the captured
// xi.db RSA plaintext block (offset 17..24).
func ServerSeedFromRSAPlaintext(rsaPlain []byte) (uint64, error) {
	if len(rsaPlain) < 25 {
		return 0, fmt.Errorf("login: rsa plaintext too short for server seed (%d bytes)", len(rsaPlain))
	}
	return binary.BigEndian.Uint64(rsaPlain[17:25]), nil
}

// BuildWireFrameFromCapture assembles the on-wire login packet that
// LoginFromCapture would send: header + RSA ciphertext + XTEA-encrypted zone.
func BuildWireFrameFromCapture(captureFrame, rsaPlain []byte, rsaKey *RSAPublicKey, serverSeed uint64) ([]byte, error) {
	if rsaKey == nil {
		return nil, fmt.Errorf("login: no RSA public key")
	}

	header, plainZone, loginType, err := ParseCapturedPlaintextFrame(captureFrame)
	if err != nil {
		return nil, err
	}
	seeds, err := LoginSeedsFromRSAPlaintext(rsaPlain)
	if err != nil {
		return nil, err
	}

	patched := append([]byte(nil), rsaPlain...)
	binary.BigEndian.PutUint64(patched[17:25], serverSeed)
	rsaCipher := rsaKey.Encrypt(patched)

	zoneCopy := append([]byte(nil), plainZone...)
	encryptedZone := xtea.EncryptBuffer(zoneCopy, seeds)

	payload := make([]byte, 0, len(header)+2+len(rsaCipher)+len(encryptedZone))
	payload = append(payload, header...)
	payload = append(payload, byte(len(rsaCipher)>>8), byte(len(rsaCipher)))
	payload = append(payload, rsaCipher...)
	payload = append(payload, encryptedZone...)

	frame := make([]byte, 0, 3+len(payload))
	frame = append(frame, loginType)
	frame = append(frame, byte(len(payload)>>8), byte(len(payload)))
	frame = append(frame, payload...)
	return frame, nil
}

// BuildWireFrameFromDecodedCapture assembles the on-wire packet from an already-decoded
// capture frame (same layout as login_frame.txt after hex decode).
func BuildWireFrameFromDecodedCapture(frame, rsaPlain []byte, rsaKey *RSAPublicKey, serverSeed uint64) ([]byte, error) {
	if rsaKey == nil {
		return nil, fmt.Errorf("login: no RSA public key")
	}
	header, plainZone, loginType, err := parseDecodedPlaintextFrame(frame)
	if err != nil {
		return nil, err
	}
	seeds, err := LoginSeedsFromRSAPlaintext(rsaPlain)
	if err != nil {
		return nil, err
	}

	patched := append([]byte(nil), rsaPlain...)
	binary.BigEndian.PutUint64(patched[17:25], serverSeed)
	rsaCipher := rsaKey.Encrypt(patched)

	zoneCopy := append([]byte(nil), plainZone...)
	encryptedZone := xtea.EncryptBuffer(zoneCopy, seeds)

	payload := make([]byte, 0, len(header)+2+len(rsaCipher)+len(encryptedZone))
	payload = append(payload, header...)
	payload = append(payload, byte(len(rsaCipher)>>8), byte(len(rsaCipher)))
	payload = append(payload, rsaCipher...)
	payload = append(payload, encryptedZone...)

	wire := make([]byte, 0, 3+len(payload))
	wire = append(wire, loginType)
	wire = append(wire, byte(len(payload)>>8), byte(len(payload)))
	wire = append(wire, payload...)
	return wire, nil
}

// BuildWireFrameFromDecodedCapturePreservingRSA encrypts the captured plaintext zone
// with the captured XTEA seeds while keeping the RSA ciphertext from the capture.
func BuildWireFrameFromDecodedCapturePreservingRSA(frame, rsaPlain []byte) ([]byte, error) {
	if len(frame) < 3+loginBodyHead+2 {
		return nil, fmt.Errorf("login: capture frame too short (%d bytes)", len(frame))
	}

	loginType := frame[0]
	body := frame[3:]
	rsaLen := int(body[loginBodyHead])<<8 | int(body[loginBodyHead+1])
	zoneStart := loginBodyHead + 2 + rsaLen
	if zoneStart > len(body) {
		return nil, fmt.Errorf("login: capture rsaLen %d overruns body (%d bytes)", rsaLen, len(body))
	}
	plainZone := append([]byte(nil), body[zoneStart:]...)
	rsaCipher := append([]byte(nil), body[loginBodyHead+2:zoneStart]...)

	seeds, err := LoginSeedsFromRSAPlaintext(rsaPlain)
	if err != nil {
		return nil, err
	}
	zoneCopy := append([]byte(nil), plainZone...)
	encryptedZone := xtea.EncryptBuffer(zoneCopy, seeds)

	payload := make([]byte, 0, loginBodyHead+2+len(rsaCipher)+len(encryptedZone))
	payload = append(payload, body[:loginBodyHead]...)
	payload = append(payload, byte(len(rsaCipher)>>8), byte(len(rsaCipher)))
	payload = append(payload, rsaCipher...)
	payload = append(payload, encryptedZone...)

	wire := make([]byte, 0, 3+len(payload))
	wire = append(wire, loginType)
	wire = append(wire, byte(len(payload)>>8), byte(len(payload)))
	wire = append(wire, payload...)
	return wire, nil
}

// AuditWireFrameBoundary prints RSA length and XTEA zone start offset for a wire frame.
func AuditWireFrameBoundary(label string, wire []byte) {
	if len(wire) < 3+loginBodyHead+2 {
		fmt.Printf("[%s] frame too short (%d bytes)\n", label, len(wire))
		return
	}
	body := wire[3:]
	rsaLen := int(body[loginBodyHead])<<8 | int(body[loginBodyHead+1])
	zoneStart := 3 + loginBodyHead + 2 + rsaLen
	fmt.Printf("[%s] wireLen=%d bodyLen=%d rsaLen=%d xteaZoneStart=0x%04X (%d)\n",
		label, len(wire), len(body), rsaLen, zoneStart, zoneStart)
}
