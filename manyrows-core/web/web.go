package web

import (
	"embed"
	"net/http"

	"github.com/rs/zerolog/log"
)

var (
	//go:embed *.html
	//go:embed assets
	//go:embed *.png
	//go:embed *.txt
	//go:embed *.ico
	//go:embed *.webmanifest
	res embed.FS
)

func GetFS() *embed.FS {
	return &res
}

func Robots(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	file, err := res.ReadFile("app/robots.txt")
	if err != nil {
		log.Err(err).Msg("robots error")
		w.WriteHeader(http.StatusInternalServerError)
	}
	_, err = w.Write(file)
	if err != nil {
		log.Err(err).Msg("robots error")
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func HandleFrontendRouterPageIndex(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/app", http.StatusTemporaryRedirect)
}

func HandleFrontendRouterPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFileFS(w, r, GetFS(), "index.html")
}
