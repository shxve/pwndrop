package core

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kgretzky/pwndrop/log"
	"github.com/kgretzky/pwndrop/storage"
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

	from_ip := ClientIP(r)

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

		if f.RedirectPath != "" && f.RedirectPath != r.URL.Path && !f.IsPaused {
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
