package network

// Game-session token ("client.pk") minting. This is the short, session-bound
// token Jagex-account logins pack into the RSA login block. It is minted from
// the JX game session (JX_SESSION_ID + JX_CHARACTER_ID) that the Jagex Launcher
// writes into RuneLite's ~/.runelite/credentials.properties.
//
// The token is short-lived: mint it as late as possible (just before the login
// write) so a slow connect/handshake does not outlive the token. See
// LoginConfig.PKMinter and cmd/loginsim -mint.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultGameSessionEndpoint mints the client.pk token from a JX session.
const DefaultGameSessionEndpoint = "https://auth.runescape.com/game-session/v1/tokens"

// DefaultCredentialsPath returns the standard RuneLite credentials file path
// (~/.runelite/credentials.properties) written by --insecure-write-credentials.
func DefaultCredentialsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".runelite", "credentials.properties")
}

// ReadJXCredentials reads JX_SESSION_ID and JX_CHARACTER_ID from a RuneLite
// credentials.properties file. These two fields are sufficient to mint the
// game-session token; the OAuth access/refresh tokens are kept by the launcher
// and are not required here.
func ReadJXCredentials(path string) (sessionID, characterID string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "JX_SESSION_ID":
			sessionID = strings.TrimSpace(v)
		case "JX_CHARACTER_ID":
			characterID = strings.TrimSpace(v)
		}
	}
	if err := sc.Err(); err != nil {
		return "", "", err
	}
	if sessionID == "" || characterID == "" {
		return "", "", fmt.Errorf("gamesession: credentials missing JX_SESSION_ID or JX_CHARACTER_ID (%s)", path)
	}
	return sessionID, characterID, nil
}

// MintResult holds a minted pk and which network path succeeded.
type MintResult struct {
	Token    string
	ViaProxy bool // true when PROXY_URL was used for the successful request
}

// MintGameSessionToken mints a fresh client.pk token from the JX session. It
// authenticates to the game-session endpoint with a browser-shaped uTLS
// ClientHello (Jagex fingerprints Go's default TLS). endpoint may be empty to
// use DefaultGameSessionEndpoint. When proxyURL is set the mint MUST egress
// through the same proxy as the game login (IP-bound session); direct fallback
// is not used because a pk minted from the host IP will be rejected on a
// proxied game connection (login code 10).
func MintGameSessionToken(endpoint, sessionID, characterID, proxyURL string, timeout time.Duration) (string, error) {
	res, err := MintGameSessionTokenWithMeta(endpoint, sessionID, characterID, proxyURL, timeout)
	if err != nil {
		return "", err
	}
	return res.Token, nil
}

func MintGameSessionTokenWithMeta(endpoint, sessionID, characterID, proxyURL string, timeout time.Duration) (MintResult, error) {
	if endpoint == "" {
		endpoint = DefaultGameSessionEndpoint
	}
	if sessionID == "" || characterID == "" {
		return MintResult{}, fmt.Errorf("gamesession: sessionID and characterID are required")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	body, err := json.Marshal(map[string]string{"accountId": characterID})
	if err != nil {
		return MintResult{}, err
	}

	doPost := func(client *http.Client) (*http.Response, error) {
		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+sessionID)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.ContentLength = int64(len(body))
		return client.Do(req)
	}

	parseResp := func(resp *http.Response, viaProxy bool) (MintResult, error) {
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return MintResult{}, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return MintResult{}, fmt.Errorf("gamesession: status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
		}
		var parsed struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(data, &parsed); err != nil {
			return MintResult{}, err
		}
		if parsed.Token == "" {
			return MintResult{}, fmt.Errorf("gamesession: response did not contain token")
		}
		return MintResult{Token: parsed.Token, ViaProxy: viaProxy}, nil
	}

	if proxyURL != "" {
		client, err := NewUTLSHTTPClient(UTLSHTTPClientOptions{ProxyURL: proxyURL, Timeout: timeout})
		if err != nil {
			return MintResult{}, fmt.Errorf("gamesession: utls client (proxy): %w", err)
		}
		resp, err := doPost(client)
		if err != nil {
			return MintResult{}, fmt.Errorf("gamesession: mint via proxy failed (pk must exit same IP as game login): %w", err)
		}
		return parseResp(resp, true)
	}

	client, err := NewUTLSHTTPClient(UTLSHTTPClientOptions{Timeout: timeout})
	if err != nil {
		return MintResult{}, fmt.Errorf("gamesession: utls client: %w", err)
	}
	resp, err := doPost(client)
	if err != nil {
		return MintResult{}, err
	}
	return parseResp(resp, false)
}

// NewCredentialsPKMinter returns a LoginConfig.PKMinter that mints a fresh
// client.pk from the RuneLite credentials file at each login. credentialsPath
// may be empty to use DefaultCredentialsPath. The returned closure reads the
// credentials fresh on every call so a re-launched launcher session is picked
// up without restarting the bot.
func NewCredentialsPKMinter(credentialsPath, proxyURL string, timeout time.Duration) func() (string, error) {
	if credentialsPath == "" {
		credentialsPath = DefaultCredentialsPath()
	}
	return func() (string, error) {
		sessionID, characterID, err := ReadJXCredentials(credentialsPath)
		if err != nil {
			return "", err
		}
		return MintGameSessionToken(DefaultGameSessionEndpoint, sessionID, characterID, proxyURL, timeout)
	}
}
