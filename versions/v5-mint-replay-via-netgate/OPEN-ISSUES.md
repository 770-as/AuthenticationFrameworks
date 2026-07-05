# v5 Open Issues

## 1. Mint egress vs game egress

`MintGameSessionToken()` uses uTLS HTTPS. With `-no-proxy`, traffic should go through netgate — but needs verification (log exit IP during mint).

**Try:** explicit `PROXY_URL` for mint only while game uses `-no-proxy`, or vice versa, to find matching pair.

## 2. Kill RuneLite before mint

`Stop-ClientHard` runs before replay. JX session in `credentials.properties` may be tied to RuneLite process lifetime.

**Try:** mint before killing RuneLite, or do not kill until after mint.

## 3. RSA / XTEA coupling

v5 patches pk into captured RSA plaintext but keeps captured XTEA seeds from wire-block attempt. Server may expect matching seed/pk/session.

**Try:** full `Login()` rebuild with minted pk + machine info parsed from frame (not LoginFromCapture).

## 4. AllowWireLogin diagnostic

`-AllowWireLogin` burns pk on wire but completes login — bot path uses `-mint` with fresh pk after.

**Try:** one AllowWireLogin capture to validate mint+Login() path without wire-block complexity.

## 5. TCP handoff (v1)

Push capture JSON to Docker bot listening on `:17494` — bot mints pk inside container with same PROXY_URL as compose.

**Try:** v1 tcp-pipeline end-to-end with Docker up before capture.
