package storage

type DbConfig struct {
	ID          int    `json:"id" storm:"id"`
	Hostname    string `json:"hostname"`
	SecretPath  string `json:"secret_path"`
	RedirectUrl string `json:"redirect_url"`
	CookieName  string `json:"cookie_name"`
	CookieToken string `json:"cookie_token"`
	// TrustCfConnectingIP: when true, honor the CF-Connecting-IP request
	// header as the real client IP (for blacklist/logging). Leave false
	// unless pwndrop is reachable only via Cloudflare (Tunnel or proxied).
	TrustCfConnectingIP bool `json:"trust_cf_connecting_ip"`
	// UaBlocklist: substrings; a request whose User-Agent contains any of
	// them is treated exactly like an unknown-path visitor (decoy redirect
	// + blacklist hit) even if it names a real hosted file.
	UaBlocklist []string `json:"ua_blocklist"`
	// ChallengeHmacKey: hex-encoded 32-byte key used to sign JS-challenge
	// blobs and the resulting one-shot pow cookie. Auto-generated on
	// first run; rotating it invalidates any in-flight challenges.
	// Persisted in the DB (JSON codec) but scrubbed from API responses in
	// api.ConfigGetHandler so it never reaches the browser.
	ChallengeHmacKey string `json:"challenge_hmac_key,omitempty"`
}

func ConfigCreate(o *DbConfig) (*DbConfig, error) {
	err := db.Save(o)
	if err != nil {
		return nil, err
	}
	return o, nil
}

func ConfigGet(id int) (*DbConfig, error) {
	var o DbConfig
	err := db.One("ID", id, &o)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

func ConfigUpdate(id int, o *DbConfig) (*DbConfig, error) {
	o.ID = id
	if err := db.Save(o); err != nil {
		return nil, err
	}
	return o, nil
}

func ConfigDelete(id int) error {
	o := &DbConfig{
		ID: id,
	}
	err := db.DeleteStruct(o)
	if err != nil {
		return err
	}
	return nil
}
