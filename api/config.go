package api

import (
	"encoding/json"
	"net/http"

	"github.com/shxve/pwndrop/storage"
	"github.com/shxve/pwndrop/utils"
)

func ConfigOptionsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
}

func ConfigGetHandler(w http.ResponseWriter, r *http.Request) {
	// #### CHECK IF AUTHENTICATED ####
	_, err := AuthSession(r)
	if err != nil {
		DumpResponse(w, "unauthorized", http.StatusUnauthorized, API_ERROR_BAD_AUTHENTICATION, nil)
		return
	}

	o, err := storage.ConfigGet(1)
	if err != nil {
		DumpResponse(w, err.Error(), http.StatusInternalServerError, API_ERROR_FILE_DATABASE_FAILED, nil)
		return
	}
	// Scrub the internal signing key before it leaves the server.
	scrubbed := *o
	scrubbed.ChallengeHmacKey = ""
	DumpResponse(w, "ok", http.StatusOK, 0, &scrubbed)
}

func ConfigUpdateHandler(w http.ResponseWriter, r *http.Request) {
	// #### CHECK IF AUTHENTICATED ####
	_, err := AuthSession(r)
	if err != nil {
		DumpResponse(w, "unauthorized", http.StatusUnauthorized, API_ERROR_BAD_AUTHENTICATION, nil)
		return
	}

	old_cfg, err := storage.ConfigGet(1)
	if err != nil {
		DumpResponse(w, err.Error(), http.StatusInternalServerError, API_ERROR_FILE_DATABASE_FAILED, nil)
		return
	}

	o := storage.DbConfig{}
	err = json.NewDecoder(r.Body).Decode(&o)
	if err != nil {
		DumpResponse(w, err.Error(), http.StatusBadRequest, API_ERROR_BAD_REQUEST, nil)
		return
	}

	if o.SecretPath == "" || o.CookieName == "" || o.CookieToken == "" {
		DumpResponse(w, "missing config variables", http.StatusBadRequest, API_ERROR_BAD_REQUEST, nil)
		return
	}

	if o.SecretPath[0] != '/' {
		o.SecretPath = "/" + o.SecretPath
	}
	if o.SecretPath != old_cfg.SecretPath {
		o.CookieName = utils.GenRandomString(4)
		o.CookieToken = utils.GenRandomHash()
	}
	// Keep the challenge HMAC key stable across config updates. The
	// admin API scrubs it out of the GET, so the client never has it to
	// send back; if it ever did, we still ignore it here.
	o.ChallengeHmacKey = old_cfg.ChallengeHmacKey

	ret, err := storage.ConfigUpdate(1, &o)
	if err != nil {
		DumpResponse(w, err.Error(), http.StatusInternalServerError, API_ERROR_FILE_DATABASE_FAILED, nil)
		return
	}
	// Same scrub as ConfigGetHandler: the signing key never leaves the
	// server. Without this it would echo back in the response body of
	// every "Save Settings" click.
	scrubbed := *ret
	scrubbed.ChallengeHmacKey = ""
	DumpResponse(w, "ok", http.StatusOK, 0, &scrubbed)
}
