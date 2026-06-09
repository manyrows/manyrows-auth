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

// HandleLivez is a pure liveness probe: it returns 200 as long as the
// process is up and serving, with NO dependency check. A liveness probe
// failing tells the orchestrator to restart the pod, so it must not flap
// on a transient database blip — that's what readiness is for.
func (handler *RequestHandler) HandleLivez(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(HealthResponse{Status: "alive", Version: handler.config.GetVersion()})
}

// HandleReadyz is a readiness probe: 200 when the service can reach the
// database, 503 otherwise. A failing readiness probe pulls the instance
// out of the load balancer (stop sending it traffic) without restarting
// it, so a brief DB hiccup degrades gracefully instead of crash-looping.
func (handler *RequestHandler) HandleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	version := handler.config.GetVersion()
	if err := handler.repo.DB().Pool().Ping(r.Context()); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(HealthResponse{Status: "unready", Version: version})
		return
	}
	_ = json.NewEncoder(w).Encode(HealthResponse{Status: "ready", Version: version})
}
