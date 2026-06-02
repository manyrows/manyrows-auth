package config

import (
	"errors"
	"fmt"
	"manyrows-core/db"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// turnstileMisconfigWarnOnce ensures the "enabled but unconfigured" warning
// in IsTurnstileEnabled is logged at most once, not on every call.
var turnstileMisconfigWarnOnce sync.Once

const devPort = 8080
const ProfileLocalDev = "dev"

// BuildVersion is the human-readable version string for this binary.
// Defaults to "dev"; release builds inject git describe via -ldflags
// (see build.sh and Dockerfile). main.go sets this from its own
// Version var on startup so the value is stamped in one place at
// build time and read everywhere via config.GetVersion().
var BuildVersion = "dev"

type Config struct {
	envPrefix string
}

// GetVersion returns the build version baked into the binary. Method
// receiver (vs. exported package var) so handler code reads it through
// the same Config it already holds for env/feature lookups.
func (conf *Config) GetVersion() string {
	return BuildVersion
}

func NewConfig(envPrefix string) *Config {
	return &Config{envPrefix: envPrefix}
}

func (conf *Config) IsDevMode() bool {
	return conf.GetProfile() == ProfileLocalDev
}

func (conf *Config) GetBaseURL() string {
	key := conf.envPrefix + "BASE_URL"
	u, ok := os.LookupEnv(key)
	if ok {
		return u
	}
	return ""
}

func (conf *Config) GetProfile() string {
	p, ok := os.LookupEnv(conf.envPrefix + "PROFILE")
	if ok {
		return p
	}
	return ProfileLocalDev
}

func (conf *Config) GetPort() (int, error) {
	p, ok := os.LookupEnv(conf.envPrefix + "PORT")
	if ok {
		port, err := strconv.Atoi(p)
		if err != nil {
			return 0, err
		}
		return port, nil
	}
	p, ok = os.LookupEnv("PORT")
	if ok {
		port, err := strconv.Atoi(p)
		if err != nil {
			return 0, err
		}
		return port, nil
	}
	return devPort, nil
}

func (conf *Config) GetLogLevel() string {
	return getStringFromEnv(conf.envPrefix+"LOG_LEVEL", "info")
}

// GetCookieDomain returns the explicit Set-Cookie domain to attach
// to admin session cookies (MRSESSION). Empty = host-only cookie,
// which is the safe self-hosted default: the cookie binds to the
// exact host the install is served from. Set this only when the
// admin host and end-user apps need to share a registrable domain
// (e.g. `MANYROWS_COOKIE_DOMAIN=example.com` so cookies set by
// `auth.example.com` are valid on `app.example.com`). Hardcoding
// a vendor default here would silently break every self-hosted
// install.
func (conf *Config) GetCookieDomain() string {
	return strings.TrimSpace(getStringFromEnv(conf.envPrefix+"COOKIE_DOMAIN", ""))
}

// GetSuperAdminEmailPin returns the operator's pre-deploy claim on the
// super-admin slot. When set, only this exact email can complete the
// first /admin/register, eliminating the "first stranger to scan the
// install wins" window described in the README. Empty (default) keeps
// the legacy behaviour where the first registrant claims the slot.
//
// The value is persisted into system_secrets at boot via the same
// first-write-wins claim path; setting this after another email has
// already registered is a no-op (logs a warning).
func (conf *Config) GetSuperAdminEmailPin() string {
	return strings.TrimSpace(getStringFromEnv(conf.envPrefix+"SUPER_ADMIN_EMAIL", ""))
}

// GetTrustedProxies returns the operator-configured allow-list of peer
// addresses ClientIP should believe forwarding headers from. See
// auth.ParseTrustedProxies for the value grammar. Empty / unset falls
// back to the auth-package default ("private": RFC1918 + loopback +
// ULA), which is safe for the common self-hosted-behind-private-
// router shape but is NOT safe behind Cloudflare or any public-edge
// proxy without explicit configuration.
func (conf *Config) GetTrustedProxies() string {
	return strings.TrimSpace(getStringFromEnv(conf.envPrefix+"TRUSTED_PROXIES", ""))
}

// GetBrandName returns the operator-facing brand name used in admin email
// subjects and bodies (admin signup, login, password reset, team invite,
// etc.). Defaults to "ManyRows" so the public OSS install reads sensibly
// out of the box; self-hosters running under their own brand set
// MANYROWS_BRAND_NAME to swap it.
func (conf *Config) GetBrandName() string {
	return strings.TrimSpace(getStringFromEnv(conf.envPrefix+"BRAND_NAME", "ManyRows"))
}

// GetJanitorIntervalMinutes returns the period between background-
// cleanup sweeps in minutes. Zero / unset = leave the janitor on its
// internal default (60 minutes). Set higher when the install is huge
// and you'd rather batch the deletes; set lower when transient tables
// fill up faster than you'd like.
func (conf *Config) GetJanitorIntervalMinutes() int {
	return envIntOrZero(conf.envPrefix + "JANITOR_INTERVAL_MINUTES")
}

// GetAttemptsRetentionDays returns the operator's preferred retention
// for the rate-limit `attempts` table. Zero / unset = janitor default
// (7 days). Attempts only matter for the rate-limit windowing query
// (last few minutes); a week is a generous floor for forensic value.
func (conf *Config) GetAttemptsRetentionDays() int {
	return envIntOrZero(conf.envPrefix + "ATTEMPTS_RETENTION_DAYS")
}

// GetAuthLogRetentionDays returns the operator's preferred retention
// for the `auth_logs` audit table. Zero / unset = janitor default
// (90 days). Bump this whenever compliance / forensics requires
// longer trails.
func (conf *Config) GetAuthLogRetentionDays() int {
	return envIntOrZero(conf.envPrefix + "AUTH_LOG_RETENTION_DAYS")
}

// GetAPIRateLimitPerMinute returns the per-key request budget for the
// server-to-server API. Zero / unset = limiter default (1200/min). Raise
// it for high-throughput integrations; lower it to tighten the blast
// radius of a leaked key.
func (conf *Config) GetAPIRateLimitPerMinute() int {
	return envIntOrZero(conf.envPrefix + "API_RATE_PER_MINUTE")
}

// envIntOrZero parses a non-negative integer env var. Returns 0 on any
// failure so the caller's "0 = default" semantics aren't broken by a
// typo in the env file.
func envIntOrZero(key string) int {
	u, ok := os.LookupEnv(key)
	if !ok {
		return 0
	}
	i, err := strconv.Atoi(strings.TrimSpace(u))
	if err != nil || i < 0 {
		log.Err(err).Str("env", key).Msg("invalid integer in env; using janitor default")
		return 0
	}
	return i
}

func getStringFromEnv(key string, def string) string {
	u, ok := os.LookupEnv(key)
	if ok {
		return u
	}
	return def
}

func (conf *Config) GetDBConfig() (db.Config, error) {
	c := db.Config{}
	c.DatabaseURL = os.Getenv(conf.envPrefix + "DATABASE_URL")
	if c.DatabaseURL == "" {
		c.DatabaseURL = os.Getenv("DATABASE_URL")
	}
	if c.DatabaseURL == "" {
		return c, fmt.Errorf("database URL not set: provide %sDATABASE_URL or DATABASE_URL", conf.envPrefix)
	}
	c.Schema = conf.GetDBSchema()
	c.MaxConns = conf.getMaxConns()
	ok, val := conf.getMaxConnIdleTimeSeconds()
	if ok {
		v := time.Second * time.Duration(val)
		c.MaxConnIdleTime = &v
	}
	ok, val = conf.getMinConns()
	if ok {
		c.MinConns = &val
	}
	ok, val = conf.getHealthCheckPeriodSeconds()
	if ok {
		v := time.Second * time.Duration(val)
		c.HealthCheckPeriod = &v
	}
	ok, val = conf.getMaxConnLifetimeSeconds()
	if ok {
		v := time.Second * time.Duration(val)
		c.MaxConnLifetime = &v
	}
	ok, val = conf.getMinIdleConns()
	if ok {
		c.MinIdleConns = &val
	}
	if ok, val := conf.getStatementTimeoutSeconds(); ok {
		v := time.Second * time.Duration(val)
		c.StatementTimeout = &v
	}
	if ok, val := conf.getConnectTimeoutSeconds(); ok {
		v := time.Second * time.Duration(val)
		c.ConnectTimeout = &v
	}
	c.ApplicationName = conf.GetDBApplicationName()
	c.SkipMigrations = envBool(conf.envPrefix+"DB_SKIP_MIGRATIONS", false)
	return c, nil
}

// GetDBApplicationName returns the value reported via Postgres's
// `application_name` GUC. Visible in pg_stat_activity /
// pg_stat_statements. Empty defaults to "manyrows" inside db.initPool;
// override per-deploy when one Postgres cluster hosts more than one
// install ("manyrows-prod", "manyrows-staging").
func (conf *Config) GetDBApplicationName() string {
	return strings.TrimSpace(os.Getenv(conf.envPrefix + "DB_APPLICATION_NAME"))
}

// getStatementTimeoutSeconds reads the optional per-query timeout
// in seconds. 0 / unset = leave the server default in place. Set
// this whenever you'd rather have one query fail loudly than have
// it pin a worker for an hour.
func (conf *Config) getStatementTimeoutSeconds() (bool, int32) {
	u, ok := os.LookupEnv(conf.envPrefix + "DB_STATEMENT_TIMEOUT_SECONDS")
	if !ok {
		return false, 0
	}
	i, err := strconv.Atoi(u)
	if err != nil || i < 0 {
		log.Err(err).Msg("invalid DB_STATEMENT_TIMEOUT_SECONDS")
		return false, 0
	}
	return true, int32(i)
}

// getConnectTimeoutSeconds reads the optional bound on the
// TCP+TLS handshake for new pool connections. Unset = wait
// forever (pgx default). Recommended on platforms where the
// DB IP can flap during a boot race.
func (conf *Config) getConnectTimeoutSeconds() (bool, int32) {
	u, ok := os.LookupEnv(conf.envPrefix + "DB_CONNECT_TIMEOUT_SECONDS")
	if !ok {
		return false, 0
	}
	i, err := strconv.Atoi(u)
	if err != nil || i <= 0 {
		log.Err(err).Msg("invalid DB_CONNECT_TIMEOUT_SECONDS")
		return false, 0
	}
	return true, int32(i)
}

// GetDBSchema returns the Postgres schema all ManyRows tables live in.
// Defaults to "manyrows" when MANYROWS_DB_SCHEMA is unset, so the
// install can share a Postgres with the operator's other apps without
// dumping its tables into public. One ManyRows instance per database
// is the supported topology — this isn't a multi-tenancy hatch.
// Identifier validation lives in db.initPool — this getter just hands
// the raw string through.
func (conf *Config) GetDBSchema() string {
	return strings.TrimSpace(os.Getenv(conf.envPrefix + "DB_SCHEMA"))
}

func (conf *Config) getMaxConns() int32 {
	u, ok := os.LookupEnv(conf.envPrefix + "POOL_MAX_CONNS")
	if ok {
		i, err := strconv.Atoi(u)
		if err != nil {
			log.Err(err).Msg("max conns")
			return 20
		}
		return int32(i)
	}
	return 20
}

func (conf *Config) GetEncryptionKey() (string, error) {
	key, ok := os.LookupEnv(conf.envPrefix + "ENCRYPTION_KEY")
	if !ok {
		return "", errors.New(conf.envPrefix + "ENCRYPTION_KEY not found")
	}
	return key, nil
}

// GetPreviousEncryptionKeys returns the optional comma-separated list of
// prior encryption keys held alongside the active one during a key
// rotation window. Each entry uses the same prefix scheme as
// MANYROWS_ENCRYPTION_KEY ("base64:..." / "raw:..." / bare). Missing
// or empty is fine — outside a rotation window there shouldn't be any
// previous keys configured.
func (conf *Config) GetPreviousEncryptionKeys() string {
	return os.Getenv(conf.envPrefix + "ENCRYPTION_KEY_PREVIOUS")
}

func (conf *Config) getMinIdleConns() (bool, int32) {
	u, ok := os.LookupEnv(conf.envPrefix + "POOL_MIN_IDLE_CONNS")
	if ok {
		i, err := strconv.Atoi(u)
		if err != nil {
			log.Err(err).Msg("")
			return false, 0
		}
		return true, int32(i)
	}
	return false, 0
}

func (conf *Config) getMinConns() (bool, int32) {
	u, ok := os.LookupEnv(conf.envPrefix + "POOL_MIN_CONNS")
	if ok {
		i, err := strconv.Atoi(u)
		if err != nil {
			log.Err(err).Msg("")
			return false, 0
		}
		return true, int32(i)
	}
	return false, 0
}

func (conf *Config) getHealthCheckPeriodSeconds() (bool, int32) {
	u, ok := os.LookupEnv(conf.envPrefix + "POOL_HEALTH_CHECK_PERIOD_SECONDS")
	if ok {
		i, err := strconv.Atoi(u)
		if err != nil {
			log.Err(err).Msg("")
			return false, 0
		}
		return true, int32(i)
	}
	return false, 0
}

func (conf *Config) getMaxConnIdleTimeSeconds() (bool, int32) {
	u, ok := os.LookupEnv(conf.envPrefix + "POOL_MAX_CONN_IDLE_TIME_SECONDS")
	if ok {
		i, err := strconv.Atoi(u)
		if err != nil {
			log.Err(err).Msg("")
			return false, 0
		}
		return true, int32(i)
	}
	return false, 0
}

func (conf *Config) getMaxConnLifetimeSeconds() (bool, int32) {
	u, ok := os.LookupEnv(conf.envPrefix + "POOL_MAX_CONN_LIFETIME_SECONDS")
	if ok {
		i, err := strconv.Atoi(u)
		if err != nil {
			log.Err(err).Msg("")
			return false, 0
		}
		return true, int32(i)
	}
	return false, 0
}

func (conf *Config) GetSessionAuthKey() (string, error) {
	seed, ok := os.LookupEnv(conf.envPrefix + "SESSION_AUTH_KEY")
	if !ok || seed == "" {
		return "", fmt.Errorf("session auth key not found")
	}
	maxVal := 64
	if len(seed) < maxVal {
		return "", fmt.Errorf("session auth key too short")
	}
	seed = seed[0:maxVal]
	return seed, nil
}

func (conf *Config) GetSessionSecretKey() (string, error) {
	seed, ok := os.LookupEnv(conf.envPrefix + "SESSION_SECRET_KEY")
	if !ok || seed == "" {
		return "", fmt.Errorf("session secret key not found")
	}
	maxVal := 32
	if len(seed) < maxVal {
		return "", fmt.Errorf("session secret key too short")
	}
	seed = seed[:maxVal]
	return seed, nil
}

// GetOTPPepper returns the server-side pepper used to hash OTP codes.
// REQUIRED for OTP auth. Auto-generated by bootstrapSecrets when
// MANYROWS_OTP_PEPPER is unset, and exported back into the env so
// this getter sees it on the same boot.
func (conf *Config) GetOTPPepper() (string, error) {
	s := strings.TrimSpace(os.Getenv(conf.envPrefix + "OTP_PEPPER"))
	if s == "" {
		return "", errors.New("missing " + conf.envPrefix + "OTP_PEPPER")
	}
	return s, nil
}

// Cloudflare Turnstile — bot-protection challenge on register.
// Falls back to Cloudflare's documented "always passes" test keys when
// unset so local dev works without an account.
// https://developers.cloudflare.com/turnstile/troubleshooting/testing/
const (
	turnstileTestSiteKey   = "1x00000000000000000000AA"
	turnstileTestSecretKey = "1x0000000000000000000000000000000AA"
)

// IsTurnstileEnabled reports whether the Turnstile bot challenge
// should be active. Off by default — the operator opts in explicitly
// with MANYROWS_TURNSTILE_ENABLED=true. When on:
//   - Prod installs need both site + secret env vars set (no real keys
//     ⇒ no widget; we don't auto-fall-back).
//   - Dev mode falls back to Cloudflare's test keys so the widget
//     renders without a Cloudflare account.
func (conf *Config) IsTurnstileEnabled() bool {
	if !envBool(conf.envPrefix+"TURNSTILE_ENABLED", false) {
		return false
	}
	if conf.IsDevMode() {
		return true
	}
	site := strings.TrimSpace(os.Getenv(conf.envPrefix + "TURNSTILE_SITE_KEY"))
	secret := strings.TrimSpace(os.Getenv(conf.envPrefix + "TURNSTILE_SECRET_KEY"))
	if site == "" || secret == "" {
		// Fail loud, not silent: the operator asked for the bot challenge
		// (TURNSTILE_ENABLED=true) but didn't supply both keys, so it's off.
		// Silently returning false turns an intended security control into a
		// no-op with no signal.
		turnstileMisconfigWarnOnce.Do(func() {
			log.Error().
				Str("env", conf.envPrefix+"TURNSTILE_ENABLED").
				Msg("turnstile enabled but TURNSTILE_SITE_KEY/TURNSTILE_SECRET_KEY are not both set — bot challenge is DISABLED; set both keys or unset TURNSTILE_ENABLED")
		})
		return false
	}
	return true
}

func (conf *Config) GetTurnstileSiteKey() string {
	if !conf.IsTurnstileEnabled() {
		return ""
	}
	v := strings.TrimSpace(os.Getenv(conf.envPrefix + "TURNSTILE_SITE_KEY"))
	if v != "" {
		return v
	}
	if conf.IsDevMode() {
		return turnstileTestSiteKey
	}
	return ""
}

func (conf *Config) GetTurnstileSecretKey() string {
	if !conf.IsTurnstileEnabled() {
		return ""
	}
	v := strings.TrimSpace(os.Getenv(conf.envPrefix + "TURNSTILE_SECRET_KEY"))
	if v != "" {
		return v
	}
	if conf.IsDevMode() {
		return turnstileTestSecretKey
	}
	return ""
}

// envBool reads a boolean env var. Accepts "1", "true", "yes" (case-
// insensitive) as truthy; everything else returns def. Trims
// whitespace so MANYROWS_TURNSTILE_ENABLED=" true " still works.
func envBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return def
	}
	return v == "1" || v == "true" || v == "yes"
}
