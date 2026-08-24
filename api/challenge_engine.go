package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/kgretzky/pwndrop/utils"
)

//go:embed interstitial.html
var interstitialTpl string

// ChallengeBits controls the SHA-256 leading-zero-bit PoW difficulty. 18
// takes a real browser ~0.5-1.2 s (single Web Worker) and single-digit
// seconds on a phone. Retune here based on real-world traffic.
const ChallengeBits = 18

// ChallengeMaxAgeSeconds is how long a challenge blob (issued in the
// interstitial HTML) is accepted at /challenge/solve. Short by design:
// forces a fresh solve per delivery, which is exactly what we want for a
// one-shot flow.
const ChallengeMaxAgeSeconds int64 = 60

// PowCookieName is the one-shot cookie a successful solve installs.
const PowCookieName = "pow"

// PowCookieTTL bounds replay windows.
const PowCookieTTL = 2 * time.Minute

// consumedNonces holds the one-shot nonces already used to serve a payload.
var (
	consumedMu     sync.Mutex
	consumedNonces = map[string]int64{} // nonce -> unix expiry
)

// StartChallengeSweeper drops expired one-shot markers so the map can't
// grow without bound. Started once at server boot.
func StartChallengeSweeper() {
	go func() {
		for {
			time.Sleep(2 * time.Minute)
			consumedMu.Lock()
			now := time.Now().Unix()
			for k, exp := range consumedNonces {
				if exp < now {
					delete(consumedNonces, k)
				}
			}
			consumedMu.Unlock()
		}
	}()
}

// ClientIP returns the client's IP for logging and blacklist keying.
// When the persisted config has TrustCfConnectingIP=true, the value of
// CF-Connecting-IP wins (Cloudflare Tunnel / proxied mode); otherwise
// falls back to net.SplitHostPort(r.RemoteAddr), IPv6-safely.
func ClientIP(r *http.Request) string {
	if Cfg != nil && Cfg.GetTrustCfConnectingIP() {
		if v := r.Header.Get("CF-Connecting-IP"); v != "" {
			return strings.TrimSpace(v)
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// -----------------------------------------------------------------------
// Challenge blob: base64url( fileID(4) | issuedAt(8) | HMAC(key, above)(32) )
// -----------------------------------------------------------------------

func challengeKey() ([]byte, error) {
	hexKey := Cfg.GetChallengeHmacKey()
	if hexKey == "" {
		return nil, fmt.Errorf("challenge HMAC key not configured")
	}
	return hex.DecodeString(hexKey)
}

// IssueChallenge creates a fresh signed challenge for the given file.
func IssueChallenge(fileID int) (string, error) {
	key, err := challengeKey()
	if err != nil {
		return "", err
	}
	body := make([]byte, 12)
	binary.BigEndian.PutUint32(body[0:4], uint32(fileID))
	binary.BigEndian.PutUint64(body[4:12], uint64(time.Now().Unix()))

	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	sig := mac.Sum(nil)

	out := append(body, sig...)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// VerifyChallenge checks signature + age; returns the file ID it was issued for.
func VerifyChallenge(c string) (int, error) {
	key, err := challengeKey()
	if err != nil {
		return 0, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil || len(raw) != 44 {
		return 0, fmt.Errorf("bad challenge encoding")
	}
	body, sig := raw[:12], raw[12:]
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return 0, fmt.Errorf("bad challenge signature")
	}
	fileID := int(binary.BigEndian.Uint32(body[0:4]))
	issuedAt := int64(binary.BigEndian.Uint64(body[4:12]))
	if time.Now().Unix()-issuedAt > ChallengeMaxAgeSeconds {
		return 0, fmt.Errorf("challenge expired")
	}
	return fileID, nil
}

// VerifyPow re-runs the client's SHA-256 leading-zero-bit check.
func VerifyPow(challenge string, nonce int64, bits int) bool {
	if bits <= 0 || bits > 256 {
		return false
	}
	h := sha256.Sum256([]byte(challenge + strconv.FormatInt(nonce, 10)))
	need := bits / 8
	rem := bits % 8
	for i := 0; i < need; i++ {
		if h[i] != 0 {
			return false
		}
	}
	if rem > 0 {
		mask := byte(0xff << (8 - rem))
		if h[need]&mask != 0 {
			return false
		}
	}
	return true
}

// -----------------------------------------------------------------------
// pow cookie: <randNonce>.<fileID>.<expiryUnix>.<hex-HMAC>
// -----------------------------------------------------------------------

// MintPowCookie constructs the one-shot cookie value.
func MintPowCookie(fileID int) (string, error) {
	key, err := challengeKey()
	if err != nil {
		return "", err
	}
	nonce := utils.GenRandomHash()
	expiry := time.Now().Add(PowCookieTTL).Unix()
	prefix := fmt.Sprintf("%s.%d.%d", nonce, fileID, expiry)

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(prefix))
	sig := hex.EncodeToString(mac.Sum(nil))
	return prefix + "." + sig, nil
}

// VerifyPowCookie parses the cookie, checks signature+expiry, and rejects
// nonces that have already been consumed. Returns the file ID and the
// nonce (so the caller can mark it consumed after a successful serve).
func VerifyPowCookie(value string) (fileID int, nonce string, err error) {
	key, kerr := challengeKey()
	if kerr != nil {
		return 0, "", kerr
	}
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return 0, "", fmt.Errorf("bad cookie format")
	}
	nonce = parts[0]
	fid, e := strconv.Atoi(parts[1])
	if e != nil {
		return 0, "", fmt.Errorf("bad fileID")
	}
	exp, e := strconv.ParseInt(parts[2], 10, 64)
	if e != nil {
		return 0, "", fmt.Errorf("bad expiry")
	}
	if exp < time.Now().Unix() {
		return 0, "", fmt.Errorf("cookie expired")
	}
	prefix := parts[0] + "." + parts[1] + "." + parts[2]
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(prefix))
	want := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(want), []byte(parts[3])) != 1 {
		return 0, "", fmt.Errorf("bad cookie signature")
	}
	consumedMu.Lock()
	_, used := consumedNonces[nonce]
	consumedMu.Unlock()
	if used {
		return 0, "", fmt.Errorf("cookie already used")
	}
	return fid, nonce, nil
}

// MarkNonceConsumed records that this one-shot nonce has been spent.
func MarkNonceConsumed(nonce string) {
	consumedMu.Lock()
	consumedNonces[nonce] = time.Now().Add(PowCookieTTL).Unix()
	consumedMu.Unlock()
}

// -----------------------------------------------------------------------
// Interstitial rendering
// -----------------------------------------------------------------------

// InterstitialData: sitekit-shaped template inputs. Phase-2 will bind
// user-visible strings to a JSON config.
type InterstitialData struct {
	Title        string
	SpinnerText  string
	ReadyText    string
	ButtonText   string
	ErrorText    string
	Challenge    string
	Bits         int
	RequireClick bool
}

var interstitialParsed = template.Must(
	template.New("i").Delims("{{", "}}").Parse(interstitialTpl),
)

// RenderInterstitial writes the interstitial HTML for the given file.
func RenderInterstitial(out *bytes.Buffer, fileID int, requireClick bool) error {
	c, err := IssueChallenge(fileID)
	if err != nil {
		return err
	}
	d := InterstitialData{
		Title:        "Preparing your download",
		SpinnerText:  "Verifying your browser…",
		ReadyText:    "Your download is ready.",
		ButtonText:   "Download",
		ErrorText:    "This link couldn't be verified. Please open it in a normal browser.",
		Challenge:    c,
		Bits:         ChallengeBits,
		RequireClick: requireClick,
	}
	return interstitialParsed.Execute(out, d)
}
