package app

import (
	"context"
	"fmt"
	"manyrows-core/api"
	"manyrows-core/auth"
	"manyrows-core/auth/client"
	config2 "manyrows-core/config"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/crypto"
	"manyrows-core/db"
	"manyrows-core/email"
	"manyrows-core/janitor"
	"manyrows-core/utils"
	"manyrows-core/webhook"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
)

type AppService struct {
	adminAuthService  *auth.Service
	clientAuthService *client.AuthService
	config            *config2.Config
	router            *chi.Mux
	requestHandler    *api.RequestHandler
	repo              *repo.Repo
	encryptor         crypto.SecretEncryptor
	webhookDispatcher *webhook.Dispatcher
	stopCleanup       context.CancelFunc
}

func NewAppService() (*AppService, error) {
	app := AppService{}
	app.config = config2.NewConfig("MANYROWS_")
	initLogger(app.config)
	dbConf, err := app.config.GetDBConfig()
	if err != nil {
		return nil, err
	}
	dbInstance, err := db.New(dbConf)
	if err != nil {
		return nil, err
	}
	repoInstance := repo.NewRepo(dbInstance)
	app.repo = repoInstance

	// Self-hosted convenience: any required secret the operator didn't
	// set in env is generated on first boot and persisted to
	// system_secrets, then exported back into the env for the rest of
	// startup. The only env var a self-hoster strictly needs is
	// DATABASE_URL.
	if err := bootstrapSecrets(context.Background(), repoInstance, "MANYROWS_"); err != nil {
		return nil, fmt.Errorf("bootstrap secrets: %w", err)
	}

	// Pin the auth package's trusted-proxy allow-list before the
	// listener accepts traffic. Unset = "private" (RFC1918 + loopback);
	// operators on Cloudflare / AWS ALB / anything public-edge MUST
	// set MANYROWS_TRUSTED_PROXIES explicitly or rate-limit IP
	// attribution will collapse onto the proxy's edge IPs.
	if err := auth.SetTrustedProxiesFromEnv(app.config.GetTrustedProxies()); err != nil {
		return nil, fmt.Errorf("trusted proxies: %w", err)
	}

	if _, err := app.config.GetOTPPepper(); err != nil {
		return nil, fmt.Errorf("MANYROWS_OTP_PEPPER: %w", err)
	}
	if _, err := app.config.GetEncryptionKey(); err != nil {
		return nil, fmt.Errorf("ENCRYPTION_KEY: %w", err)
	}

	// Construct the encryptor + transparently-encrypting system_secrets
	// wrapper before anything reads sensitive rows. Every callee that
	// touches system_secrets (jwks loader, email SMTP-config reader,
	// SMTP-config writer) gets the wrapped store so values are encrypted
	// at rest under the install's encryption_key. encryption_key itself
	// stays plaintext — see bootstrap_secrets.go for why.
	encryptor := crypto.NewMySecretEncryptor(app.config)
	app.encryptor = encryptor
	secureSecrets := crypto.NewEncryptingSystemSecretsStore(repoInstance, encryptor)

	app.adminAuthService, err = auth.NewAuthService(app.config, repoInstance)
	if err != nil {
		return nil, err
	}
	app.clientAuthService, err = client.NewAuthService(app.config, repoInstance, secureSecrets)
	if err != nil {
		return nil, err
	}

	email.SetBrand(app.config.GetBrandName())
	emailService := email.NewEmailService(app.config.IsDevMode(), secureSecrets)

	// Wire new-device detection: the client auth service records each login's
	// device and calls back here to send the alert email when it's a device
	// the user hasn't been seen on before (gated per app).
	app.clientAuthService.SetNewDeviceNotifier(newDeviceAlertNotifier(repoInstance, emailService))

	app.requestHandler = api.NewRequestHandler(
		repoInstance,
		app.adminAuthService,
		app.clientAuthService,
		emailService,
		app.config,
		encryptor,
		secureSecrets)

	// Webhook dispatcher
	app.webhookDispatcher = webhook.NewDispatcher(repoInstance, app.config.IsDevMode(), encryptor)
	app.webhookDispatcher.Start(context.Background())
	app.requestHandler.SetWebhookDispatcher(app.webhookDispatcher)

	// Background janitor. Sweeps transient tables (dpop_replay, OTPs,
	// expired refresh tokens, etc.) and trims event logs (attempts,
	// auth_logs) per the operator's retention settings. Without this,
	// every transient-data table grows for the life of the install.
	janitorCfg := janitor.Config{
		Interval:                 time.Duration(app.config.GetJanitorIntervalMinutes()) * time.Minute,
		AttemptsRetention:        time.Duration(app.config.GetAttemptsRetentionDays()) * 24 * time.Hour,
		AuthLogRetention:         time.Duration(app.config.GetAuthLogRetentionDays()) * 24 * time.Hour,
		WebhookDeliveryRetention: time.Duration(app.config.GetWebhookDeliveryRetentionDays()) * 24 * time.Hour,
	}
	janitorCtx, janitorCancel := context.WithCancel(context.Background())
	app.stopCleanup = janitorCancel
	janitor.New(repoInstance, janitorCfg).Start(janitorCtx)

	err = app.initRouter()
	if err != nil {
		return nil, err
	}
	// Super-admin email resolution. Three sources, in priority order:
	//
	//   1. MANYROWS_SUPER_ADMIN_EMAIL (optional pre-deploy pin). When
	//      set the operator locks the first-admin slot to a specific
	//      email before exposing the install, closing the "first
	//      stranger to scan the install wins" window. The value is
	//      persisted via PutSystemSecret (first-write-wins) so a later
	//      boot with the env unset still sees the pin.
	//   2. system_secrets("super_admin_email") — whatever the first
	//      registrant or a previous boot's env pin wrote.
	//   3. nothing — registration is open until the first
	//      /admin/register commits, then the AdminRegister handler
	//      claims the role.
	//
	// Setting the env to a value DIFFERENT from an already-claimed row
	// is a no-op (system_secrets is first-write-wins) and gets logged
	// so the discrepancy is visible. Recovery from a wrong pin means
	// editing system_secrets directly.
	bootCtx := context.Background()
	if envPin := app.config.GetSuperAdminEmailPin(); envPin != "" {
		normalised, vr := auth.ValidateEmail(envPin)
		if !vr.Ok() {
			log.Warn().Str("env_pin", utils.MaskEmail(envPin)).Msg("MANYROWS_SUPER_ADMIN_EMAIL is malformed; ignored")
		} else if stored, err := repoInstance.PutSystemSecret(bootCtx, "super_admin_email", normalised); err != nil {
			log.Err(err).Msg("super-admin pin: PutSystemSecret failed (continuing without pin)")
		} else if stored != normalised {
			log.Warn().
				Str("env_pin", utils.MaskEmail(normalised)).
				Str("stored", utils.MaskEmail(stored)).
				Msg("MANYROWS_SUPER_ADMIN_EMAIL conflicts with existing system_secrets row; using stored value")
		} else {
			log.Info().Str("email", utils.MaskEmail(normalised)).Msg("super-admin email pinned from env")
		}
	}
	if v, err := repoInstance.GetSystemSecret(bootCtx, "super_admin_email"); err == nil && v != "" {
		core.SetSuperAdminEmail(v)
	}

	// BASE_URL: env wins, else load the value the first-admin pinned
	// from their /admin/register hostname. Exported via os.Setenv so
	// the existing config.GetBaseURL() callers stay env-only.
	if app.config.GetBaseURL() == "" {
		if v, err := repoInstance.GetSystemSecret(context.Background(), "base_url"); err == nil && v != "" {
			_ = os.Setenv("MANYROWS_BASE_URL", v)
		}
	}

	return &app, nil
}

func (a *AppService) GetRequestHandler() *api.RequestHandler {
	return a.requestHandler
}

func (a *AppService) Start() error {
	port, err := a.config.GetPort()
	if err != nil {
		log.Err(err).Msg("Unable to get port")
		return err
	}
	addr := ":" + strconv.Itoa(port)

	srv := &http.Server{
		Addr:              addr,
		Handler:           a.router,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	// Graceful shutdown on SIGTERM/SIGINT
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-done
		log.Info().Msg("Shutting down gracefully…")

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			log.Err(err).Msg("HTTP server shutdown error")
		}
	}()

	log.Info().Msgf("Listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		a.Shutdown()
		return err
	}

	a.Shutdown()
	return nil
}

func (a *AppService) Shutdown() {
	if a.stopCleanup != nil {
		a.stopCleanup()
	}
	if a.webhookDispatcher != nil {
		a.webhookDispatcher.Stop()
	}
	a.repo.Shutdown()
}

func initLogger(config *config2.Config) {
	if config.IsDevMode() {
		zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	}
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
		return filepath.Base(file) + ":" + strconv.Itoa(line)
	}
	log.Logger = log.With().Caller().Logger()
	// Unseeded contexts fall back to the fully-configured global logger,
	// so reqLog(ctx) is a behavior-preserving drop-in for the global log.
	zerolog.DefaultContextLogger = &log.Logger
	level, err := zerolog.ParseLevel(config.GetLogLevel())
	if err != nil {
		println("Parse Level error" + err.Error())
		level = zerolog.InfoLevel
	}
	if config.IsDevMode() {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(level)
	}
	utils.SetAnonymizeIPInLogs(config.IsLogAnonymizeIPEnabled())
}
