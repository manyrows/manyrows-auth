package appkit

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
)

//go:embed appkit
var res embed.FS

// version is a strong ETag derived from the *content* of the embedded
// AppKit bundle, computed once at init. It changes automatically
// whenever the built assets change, so there is no version file to
// remember to bump — a stale browser cache is impossible because a
// different bundle always produces a different tag, and an unchanged
// bundle always produces the same one (good for caching).
var version string

func GetFS() *embed.FS {
	return &res
}

func HandleFrontendRouterPageIndex(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/appkit/app", http.StatusTemporaryRedirect)
}

func HandleFrontendRouterPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFileFS(w, r, GetFS(), "index.html")
}

func init() {
	version = hashEmbeddedAssets()
}

// hashEmbeddedAssets walks the embedded appkit/ tree in deterministic
// order (fs.WalkDir visits lexically) and folds every file's path and
// bytes into one SHA-256. Path is mixed in too so a rename alone still
// busts the cache. Returns a quoted strong ETag per RFC 7232; the
// 64-bit prefix is ample for cache-busting collision resistance.
func hashEmbeddedAssets() string {
	h := sha256.New()
	_ = fs.WalkDir(&res, "appkit", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := res.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		h.Write([]byte(path))
		h.Write([]byte{0})
		h.Write(b)
		return nil
	})
	return `"` + hex.EncodeToString(h.Sum(nil))[:16] + `"`
}

func GetVersion() string {
	return version
}
