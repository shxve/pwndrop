package core

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shxve/pwndrop/api"
	"github.com/shxve/pwndrop/log"
	"github.com/shxve/pwndrop/storage"
)

// isUaBlocked returns true when the request's User-Agent contains any
// substring from the configured blocklist (case-insensitive).
func isUaBlocked(ua string, blocklist []string) bool {
	if ua == "" || len(blocklist) == 0 {
		return false
	}
	lua := strings.ToLower(ua)
	for _, needle := range blocklist {
		n := strings.TrimSpace(strings.ToLower(needle))
		if n == "" {
			continue
		}
		if strings.Contains(lua, n) {
			return true
		}
	}
	return false
}

const BLACKLIST_JAIL_TIME_SECS = 10 * 60
const BLACKLIST_HITS_LIMIT = 10

type BlacklistItem struct {
	hits     int
	last_hit time.Time
}

type Http struct {
	srv *Server
}

func NewHttp(srv *Server) (*Http, error) {
	s := &Http{
		srv: srv,
	}
	return s, nil
}

func (s *Http) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data_dir := Cfg.GetDataDir()

	from_ip := api.ClientIP(r)

	if r.Method == "GET" {
		f, status, err := s.srv.GetFile(r.URL.Path)
		if err != nil {
			log.Error("http: get: %s: %s (%s)", r.URL.Path, err, from_ip)
			err := s.killConnection(w, status)
			if err != nil {
				log.Error("http: %s (%s)", err, from_ip)
			}
			return
		}

		// User-Agent blocklist (unless the file has been marked bypass).
		if !f.UaBypass {
			if isUaBlocked(r.Header.Get("User-Agent"), Cfg.GetUaBlocklist()) {
				log.Warning("http: ua-blocked '%s' -> %s (%s)", r.Header.Get("User-Agent"), r.URL.Path, from_ip)
				s.srv.blockAsUnknown(w, r, from_ip)
				return
			}
		}

		// Hit limit: 0 means unlimited. Once reached, behave like unknown.
		if f.MaxHits > 0 && f.HitCount >= f.MaxHits {
			log.Warning("http: hit-limit reached for %s (%d/%d) (%s)", r.URL.Path, f.HitCount, f.MaxHits, from_ip)
			s.srv.blockAsUnknown(w, r, from_ip)
			return
		}

		// Access token: if required, ?t=<token> must match the file's
		// AccessToken exactly. Same block-as-unknown behavior on mismatch
		// so a scanner can't tell a token-gated file exists.
		if f.RequireToken {
			given := r.URL.Query().Get("t")
			if given == "" || subtle.ConstantTimeCompare([]byte(given), []byte(f.AccessToken)) != 1 {
				log.Warning("http: bad/missing token for %s (%s)", r.URL.Path, from_ip)
				s.srv.blockAsUnknown(w, r, from_ip)
				return
			}
		}

		// JS challenge: if enabled and the request has no valid pow cookie,
		// serve the interstitial on r.URL.Path (address bar stays stable
		// whether the target hit UrlPath or a RedirectPath alias). A valid
		// cookie is atomically consumed the moment it verifies — same
		// cookie presented twice (even concurrently) only serves once.
		// We also skip the RedirectPath 302 on success so the same URL
		// delivers both the interstitial and the file.
		challengePassed := false
		if f.ChallengeEnabled {
			passed := false
			if ck, err := r.Cookie(api.PowCookieName); err == nil {
				if fid, verr := api.TryConsumePowCookie(ck.Value); verr == nil && fid == f.ID {
					passed = true
				}
			}
			if !passed {
				var buf bytes.Buffer
				if err := api.RenderInterstitial(&buf, f.ID, f.ChallengeRequireClick); err != nil {
					log.Error("http: interstitial render for %s: %v", r.URL.Path, err)
					s.killConnection(w, 500)
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(200)
				w.Write(buf.Bytes())
				return
			}
			challengePassed = true
		}

		// Only follow the RedirectPath alias when the challenge is off (or
		// the target hasn't solved yet - which we returned on above). When
		// the challenge has passed we deliver the payload at r.URL.Path so
		// the address bar stays stable through the whole flow.
		if !challengePassed && f.RedirectPath != "" && f.RedirectPath != r.URL.Path && !f.IsPaused {
			log.Error("http: get: %s: redirecting to '%s' (%s)", r.URL.Path, f.RedirectPath, from_ip)
			http.Redirect(w, r, f.RedirectPath, http.StatusFound)
			return
		}

		mime_type := f.MimeType
		if f.IsPaused {
			mime_type = f.SubMimeType
		}
		fpath := filepath.Join(data_dir, "files", f.Filename)
		fo, err := os.Open(fpath)
		if err != nil {
			log.Error("http: file: %s: %s (%s)", f.Filename, err, from_ip)
			return
		}
		defer fo.Close()

		// (The pow nonce, if any, was already consumed atomically inside
		// TryConsumePowCookie above — no separate mark step needed.)

		w.Header().Set("Content-Type", mime_type)
		w.WriteHeader(200)
		io.Copy(w, fo)

		// Count the download (only successful serves of the real payload;
		// facades and 302-redirects to a distinct path are not counted).
		if !f.IsPaused {
			if err := storage.FileIncHits(f.ID); err != nil {
				log.Error("http: FileIncHits(%d): %v", f.ID, err)
			}
		}
		return
	}
	err := s.killConnection(w, 404)
	if err != nil {
		log.Error("http: %s (%s)", err, from_ip)
	}
}

func (s *Http) killConnection(w http.ResponseWriter, status int) error {
	if status > 0 {
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(status)
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		return fmt.Errorf("connection hijacking not supported")
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}
