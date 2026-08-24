package storage

import (
	"os"
	"path/filepath"

	"github.com/asdine/storm/v3"

	"github.com/shxve/pwndrop/log"
	"github.com/shxve/pwndrop/utils"
)

var db *storm.DB

func Open(path string) error {
	var err error

	err = os.MkdirAll(filepath.Dir(path), 0700)
	if err != nil {
		return err
	}

	db, err = storm.Open(path)
	if err != nil {
		return err
	}

	err = db.Init(&DbFile{})
	if err != nil {
		return err
	}
	err = db.Init(&DbSubFile{})
	if err != nil {
		return err
	}
	err = db.Init(&DbUser{})
	if err != nil {
		return err
	}
	err = db.Init(&DbSession{})
	if err != nil {
		return err
	}
	err = db.Init(&DbConfig{})
	if err != nil {
		return err
	}

	// initialize config
	err = initConfig()
	if err != nil {
		return err
	}

	return nil
}

// DefaultUaBlocklist: seeded on fresh installs. Substring match, case-
// insensitive. Operators can edit the list from the admin panel.
var DefaultUaBlocklist = []string{
	"curl/", "wget/", "python-requests", "python-urllib", "go-http-client",
	"httpclient", "libwww-perl", "okhttp", "java/", "ruby",
	"scrapy", "masscan", "nmap", "zgrab", "nuclei", "sqlmap",
	"bot", "crawler", "spider", "slurp", "facebookexternalhit",
	"slackbot", "discordbot", "telegrambot", "whatsapp", "twitterbot",
	"bingpreview", "linkedinbot", "embedly", "quora link preview",
	"vkshare", "outbrain", "pinterest", "developers.google.com/+/web/snippet",
}

func initConfig() error {
	o, err := ConfigGet(1)
	if err != nil {
		o = &DbConfig{
			ID:               1,
			SecretPath:       "/pwndrop",
			RedirectUrl:      "https://www.youtube.com/watch?v=oHg5SJYRHA0",
			CookieName:       utils.GenRandomString(4),
			CookieToken:      utils.GenRandomHash(),
			UaBlocklist:      DefaultUaBlocklist,
			ChallengeHmacKey: utils.GenRandomHash(),
		}
		_, err = ConfigCreate(o)
		if err != nil {
			return err
		}
	} else {
		// Backfill fields added in later versions.
		dirty := false
		if o.UaBlocklist == nil {
			o.UaBlocklist = DefaultUaBlocklist
			dirty = true
		}
		if o.ChallengeHmacKey == "" {
			o.ChallengeHmacKey = utils.GenRandomHash()
			dirty = true
		}
		if dirty {
			if _, err := ConfigUpdate(1, o); err != nil {
				return err
			}
		}
	}
	log.Debug("secret_path: %s", o.SecretPath)
	return nil
}
