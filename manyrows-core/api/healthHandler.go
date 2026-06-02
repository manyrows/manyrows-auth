package api

import (
	"encoding/json"
	"net/http"
)

// HealthResponse is the /health payload. version is the build-time
// string stamped into the binary (see config.BuildVersion); the admin
// UI fetches it once at boot to surface in the sidebar footer.
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
}

// HandleHealth is a lightweight liveness/readiness probe.
// Returns 200 if the service can reach the database, 503 otherwise.
func (handler *RequestHandler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	version := handler.config.GetVersion()
	if err := handler.repo.DB().Pool().Ping(r.Context()); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(HealthResponse{Status: "unhealthy", Version: version})
		return
	}
	_ = json.NewEncoder(w).Encode(HealthResponse{Status: "healthy", Version: version})
}
