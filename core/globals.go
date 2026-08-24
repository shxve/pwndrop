package core

import (
	"net"
	"net/http"
	"strings"

	"github.com/kgretzky/pwndrop/config"
)

var Cfg *config.Config

// ClientIP returns the client's IP for logging and blacklist keying.
// When the persisted config has TrustCfConnectingIP=true, the value of the
// CF-Connecting-IP request header wins (Cloudflare Tunnel / proxied mode);
// otherwise falls back to net.SplitHostPort(r.RemoteAddr), IPv6-safely.
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
