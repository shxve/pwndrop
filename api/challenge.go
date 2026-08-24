package api

import (
	"encoding/json"
	"net/http"

	"github.com/shxve/pwndrop/log"
)

// ChallengeSolveHandler receives the PoW nonce and env-probe results from
// the interstitial page. On success it sets the one-shot pow cookie the
// subsequent GET on the file URL will use.
func ChallengeSolveHandler(w http.ResponseWriter, r *http.Request) {
	// CORS preflight-ish default; the interstitial is same-origin so this
	// is mostly noise, but keep consistent with the other API OPTIONS.
	w.Header().Set("Access-Control-Allow-Methods", "POST,OPTIONS")
	if r.Method == "OPTIONS" {
		return
	}

	type Probes struct {
		Webdriver bool `json:"webdriver"`
		Precise   bool `json:"precise"`
		EvalOk    bool `json:"evalok"`
		Subtle    bool `json:"subtle"`
	}
	type Req struct {
		C string `json:"c"` // challenge blob
		N int64  `json:"n"` // nonce
		P Probes `json:"p"` // env probes
	}

	from_ip := ClientIP(r)

	var in Req
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		log.Warning("challenge: bad body from %s: %v", from_ip, err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// All four probes must pass. A real browser answers `true` to every
	// one; jsdom / hermes / lightweight sandboxes fail at least one.
	if !(in.P.Webdriver && in.P.Precise && in.P.EvalOk && in.P.Subtle) {
		log.Warning("challenge: probe failed from %s: %+v", from_ip, in.P)
		http.Error(w, "verification failed", http.StatusForbidden)
		return
	}

	fileID, err := VerifyChallenge(in.C)
	if err != nil {
		log.Warning("challenge: bad blob from %s: %v", from_ip, err)
		http.Error(w, "verification failed", http.StatusForbidden)
		return
	}

	if !VerifyPow(in.C, in.N, ChallengeBits) {
		log.Warning("challenge: bad PoW from %s (fileID=%d)", from_ip, fileID)
		http.Error(w, "verification failed", http.StatusForbidden)
		return
	}

	cookieVal, err := MintPowCookie(fileID)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     PowCookieName,
		Value:    cookieVal,
		Path:     "/",
		MaxAge:   int(PowCookieTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"ok":true}`))
}
