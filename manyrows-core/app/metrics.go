package app

import (
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metrics holds the Prometheus registry and the HTTP collectors. A
// dedicated registry (rather than the global default) keeps the exposed
// set explicit and the package testable.
type metrics struct {
	registry    *prometheus.Registry
	reqTotal    *prometheus.CounterVec
	reqDuration *prometheus.HistogramVec
}

// newMetrics builds the registry with Go-runtime and process collectors
// (goroutines, GC, memory, fds, CPU), a build-info gauge, and the HTTP
// request collectors.
func newMetrics(version string) *metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "manyrows_build_info",
		Help: "Build information; constant 1, labelled with the binary version.",
	}, []string{"version"})
	buildInfo.WithLabelValues(version).Set(1)
	reg.MustRegister(buildInfo)

	reqTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "manyrows_http_requests_total",
		Help: "Total HTTP requests, by method, matched route pattern, and status code.",
	}, []string{"method", "route", "status"})
	reqDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "manyrows_http_request_duration_seconds",
		Help:    "HTTP request latency, by method, matched route pattern, and status code.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route", "status"})
	reg.MustRegister(reqTotal, reqDuration)

	return &metrics{registry: reg, reqTotal: reqTotal, reqDuration: reqDuration}
}

// registerDBPool exposes pgx pool saturation as gauges, read at scrape
// time. These are the first thing to watch when the API slows under load.
func (m *metrics) registerDBPool(pool *pgxpool.Pool) {
	gauge := func(name, help string, fn func() float64) {
		m.registry.MustRegister(prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{Name: name, Help: help}, fn))
	}
	gauge("manyrows_db_pool_total_conns", "Total connections in the pgx pool (idle + in-use).",
		func() float64 { return float64(pool.Stat().TotalConns()) })
	gauge("manyrows_db_pool_acquired_conns", "Connections currently checked out (in use).",
		func() float64 { return float64(pool.Stat().AcquiredConns()) })
	gauge("manyrows_db_pool_idle_conns", "Idle connections held in the pool.",
		func() float64 { return float64(pool.Stat().IdleConns()) })
	gauge("manyrows_db_pool_max_conns", "Maximum connections the pool is allowed to open.",
		func() float64 { return float64(pool.Stat().MaxConns()) })
}

// middleware records each request's count and latency, labelled by the
// matched chi route PATTERN (e.g. /x/{workspaceSlug}/api/users/{userId})
// rather than the raw path, so the label set stays bounded.
func (m *metrics) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(ww, r)

		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "unmatched"
		}
		status := ww.Status()
		if status == 0 {
			status = http.StatusOK // handler returned without WriteHeader
		}
		statusStr := strconv.Itoa(status)

		m.reqTotal.WithLabelValues(r.Method, route, statusStr).Inc()
		m.reqDuration.WithLabelValues(r.Method, route, statusStr).Observe(time.Since(start).Seconds())
	})
}

// handler serves the Prometheus exposition. When token is non-empty it
// requires `Authorization: Bearer <token>` (constant-time compared);
// otherwise it is open and the operator is expected to restrict it at the
// reverse proxy or private network.
func (m *metrics) handler(token string) http.Handler {
	prom := promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
	if token == "" {
		return prom
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		presented := strings.TrimPrefix(r.Header.Get("Authorization"), prefix)
		if !strings.HasPrefix(r.Header.Get("Authorization"), prefix) ||
			subtle.ConstantTimeCompare([]byte(presented), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		prom.ServeHTTP(w, r)
	})
}
