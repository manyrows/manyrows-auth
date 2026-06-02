package utils

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

func GetPathUUID(key string, r *http.Request) (uuid.UUID, error) {
	val := chi.URLParam(r, key)
	u, err := uuid.FromString(val)
	if err != nil {
		return uuid.Nil, err
	}
	return u, nil
}

func GetPathString(key string, r *http.Request) string {
	return chi.URLParam(r, key)
}

func WriteJsonWithStatusCode(w http.ResponseWriter, v any, code int) {
	if code <= 0 {
		code = http.StatusBadRequest
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	body, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		log.Err(err).Msg("json marshal error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(code)
	if _, err = w.Write(body); err != nil {
		log.Err(err).Msg("http write error")
	}
}

func WriteJson(w http.ResponseWriter, v any) {
	WriteJsonWithStatusCode(w, v, http.StatusOK)
}

// Body-size limits are enforced one layer up at the router level via
// the maxBodySize middleware (see app/router.go's createBaseRouter,
// currently 1 MB). All routes mounted under the base router inherit
// that cap, so ReadAll here is bounded regardless of input — chi's
// MaxBytesReader closes the connection on overflow before we reach
// json.Unmarshal.
func ReadJson(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Err(err).Msg("")
		http.Error(w, "", http.StatusBadRequest)
		return false
	}
	err = json.Unmarshal(body, v)
	if err != nil {
		log.Err(err).Msg("")
		http.Error(w, "", http.StatusBadRequest)
		return false
	}
	return true
}

func NewUUID() uuid.UUID {
	return uuid.Must(uuid.NewV7())
}
