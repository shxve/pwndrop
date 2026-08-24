package storage

import (
	"github.com/kgretzky/pwndrop/log"
	"github.com/kgretzky/pwndrop/utils"
)

type DbFile struct {
	ID           int    `json:"id" storm:"id,increment"`
	Uid          int    `json:"uid" storm:"index"`
	Name         string `json:"name"`
	Filename     string `json:"fname"`
	FileSize     int64  `json:"fsize"`
	UrlPath      string `json:"url_path" storm:"unique"`
	MimeType     string `json:"mime_type"`
	OrigMimeType string `json:"orig_mime_type"`
	CreateTime   int64  `json:"create_time" storm:"index"`
	IsEnabled    bool   `json:"is_enabled"`
	IsPaused     bool   `json:"is_paused"`
	RedirectPath string `json:"redirect_path" storm:"unique"`
	SubName      string `json:"sub_name"`
	SubMimeType  string `json:"sub_mime_type"`
	RefSubFile   int    `json:"ref_sub_file"`
	// MaxHits: max successful downloads before the file behaves like
	// disabled. 0 = unlimited (default).
	MaxHits int64 `json:"max_hits"`
	// HitCount: successful downloads served so far. Incremented on each
	// served GET; not touched for facade/redirect responses.
	HitCount int64 `json:"hit_count"`
	// UaBypass: when true, this file ignores the global UA blocklist
	// (useful when you deliberately want e.g. curl to pull it).
	UaBypass bool `json:"ua_bypass"`
	// RequireToken: when true, requests must include ?t=<AccessToken> or
	// they are treated like an unknown-path visitor (decoy + blacklist).
	RequireToken bool `json:"require_token"`
	// AccessToken: 32-hex-char shared secret. Pre-generated at upload
	// time so it is ready to hand out the moment RequireToken is flipped
	// on; the operator can rotate it any time via FileRegenerateToken.
	AccessToken string `json:"access_token"`
	// ChallengeEnabled: when true, GETs are served a small JS-PoW
	// interstitial before the payload. Filters link-preview bots and
	// low-budget URL sandboxes that don't run (or don't wait for) JS.
	ChallengeEnabled bool `json:"challenge_enabled"`
	// ChallengeRequireClick: when true, the interstitial reveals a
	// Download button on successful solve instead of auto-firing the
	// download. Ignored when ChallengeEnabled is false.
	ChallengeRequireClick bool `json:"challenge_require_click"`
}

func FileCreate(o *DbFile) (*DbFile, error) {
	err := db.Save(o)
	if err != nil {
		return nil, err
	}
	log.Debug("file id: %d", o.ID)
	return o, nil
}

func FileList() ([]DbFile, error) {
	var dbos []DbFile

	err := db.All(&dbos)
	if err != nil {
		return nil, err
	}
	/*
		for _, dbo := range dbos {
			log.Debug("filelist: sub_id: %d", dbo.RefSubFile)
			if dbo.RefSubFile > 0 {
				subf, err := SubFileGet(f.RefSubFile)
				if err == nil {
					jf.SubFile = subf
				}
			}
			ret = append(ret, dbo)
		}*/
	return dbos, nil
}

func FileGet(id int) (*DbFile, error) {
	var o DbFile
	err := db.One("ID", id, &o)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

func FileGetByUrl(url string) (*DbFile, error) {
	var o DbFile
	err := db.One("UrlPath", url, &o)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

func FileGetByRedirectUrl(url string) (*DbFile, error) {
	var o DbFile
	err := db.One("RedirectPath", url, &o)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

func FileDirExists(url string) bool {
	var o []DbFile
	if url == "" {
		return false
	}
	if url[len(url)-1] != '/' {
		url += "/"
	}
	err := db.Prefix("UrlPath", url, &o)
	if err != nil {
		return false
	}
	return true
}

func FileDelete(id int) error {
	f := &DbFile{
		ID: id,
	}
	err := db.DeleteStruct(f)
	if err != nil {
		return err
	}
	return nil
}

func FileUpdate(id int, o *DbFile) (*DbFile, error) {
	// Save the full struct: this preserves zero-value fields (empty
	// RedirectPath, MaxHits=0, UaBypass=false) that storm.Update would
	// otherwise skip. Callers are expected to pass a fully-populated
	// struct (typically FileGet(id) with the desired mutations applied).
	o.ID = id
	if err := db.Save(o); err != nil {
		return nil, err
	}
	return o, nil
}

// FileIncHits atomically-ish (single DB transaction) bumps HitCount by 1.
func FileIncHits(id int) error {
	f, err := FileGet(id)
	if err != nil {
		return err
	}
	return db.UpdateField(&DbFile{ID: id}, "HitCount", f.HitCount+1)
}

func FileResetSubFile(id int) (*DbFile, error) {
	if err := db.UpdateField(&DbFile{ID: id}, "RefSubFile", 0); err != nil {
		return nil, err
	}
	o, err := FileGet(id)
	if err != nil {
		return nil, err
	}
	return o, nil
}

func FileEnable(id int, enable bool) (*DbFile, error) {
	if err := db.UpdateField(&DbFile{ID: id}, "IsEnabled", enable); err != nil {
		return nil, err
	}
	o, err := FileGet(id)
	if err != nil {
		return nil, err
	}
	return o, nil
}

func FilePause(id int, pause bool) (*DbFile, error) {
	if err := db.UpdateField(&DbFile{ID: id}, "IsPaused", pause); err != nil {
		return nil, err
	}
	o, err := FileGet(id)
	if err != nil {
		return nil, err
	}
	return o, nil
}

// FileRegenerateToken assigns a fresh random AccessToken to the file and
// returns the updated record.
func FileRegenerateToken(id int) (*DbFile, error) {
	tok := utils.GenRandomHash()
	if err := db.UpdateField(&DbFile{ID: id}, "AccessToken", tok); err != nil {
		return nil, err
	}
	return FileGet(id)
}
