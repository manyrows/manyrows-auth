package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"manyrows-core/app"
	"manyrows-core/config"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/crypto"
	"manyrows-core/db"
	"manyrows-core/encmigrate"

	"github.com/rs/zerolog/log"
)

// Version is the build version stamped at link time via:
//
//	go build -ldflags="-X main.Version=$(git describe --tags --always --dirty)"
//
// `go run` and unstamped local builds keep the "dev" default. The value
// flows into config.BuildVersion below so every package can read it
// through the existing Config plumbing.
var Version = "dev"

func main() {
	config.BuildVersion = Version
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "migrate-encryption":
			if err := runEncryptionMigration(); err != nil {
				log.Fatal().Err(err).Msg("encryption migration failed")
			}
			return
		case "reset-admin-2fa":
			email := ""
			if len(os.Args) > 2 {
				email = os.Args[2]
			}
			if err := runResetAdminTOTP(email); err != nil {
				log.Fatal().Err(err).Msg("reset-admin-2fa failed")
			}
			return
		case "help", "-h", "--help":
			printUsage()
			return
		}
	}

	ap, err := app.NewAppService()
	if err != nil {
		panic(err)
	}
	err = ap.Start()
	if err != nil {
		panic(err)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  web                          start the HTTP server (default)")
	fmt.Fprintln(os.Stderr, "  web migrate-encryption       walk every server-encrypted column and rewrite under the active key")
	fmt.Fprintln(os.Stderr, "  web reset-admin-2fa <email>  clear 2FA on a locked-out admin/owner account (sign in with the password, then re-enrol)")
	fmt.Fprintln(os.Stderr, "  web help                     print this message")
}

// runResetAdminTOTP clears the TOTP enrolment for the admin account with the
// given email. It is the out-of-band recovery for a sole owner/super-admin
// locked out of the console (lost authenticator + backup codes) when no other
// owner is available to reset it via the dashboard. Boots only config + db +
// repo — no HTTP server, no background workers.
func runResetAdminTOTP(email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return fmt.Errorf("usage: reset-admin-2fa <email>")
	}

	cfg := config.NewConfig("MANYROWS_")
	dbConf, err := cfg.GetDBConfig()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	dbInstance, err := db.New(dbConf)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	repoInstance := repo.NewRepo(dbInstance)

	if err := repoInstance.DisableAccountTOTPByEmail(context.Background(), email); err != nil {
		if errors.Is(err, core.ErrAccountNotFound) {
			return fmt.Errorf("no admin account found for %q", email)
		}
		return err
	}

	log.Info().Str("email", email).Msg("reset-admin-2fa: 2FA cleared — sign in with the account password, then re-enrol")
	return nil
}

// runEncryptionMigration boots the minimum needed (config, db, repo,
// encryptor) and runs the encmigrate walker. No HTTP server, no
// background workers — this is a one-shot command.
func runEncryptionMigration() error {
	cfg := config.NewConfig("MANYROWS_")

	dbConf, err := cfg.GetDBConfig()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	dbInstance, err := db.New(dbConf)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}

	repoInstance := repo.NewRepo(dbInstance)
	enc := crypto.NewMySecretEncryptor(cfg)

	log.Info().Msg("encryption migration: starting")
	stats, err := encmigrate.Run(context.Background(), repoInstance, enc)
	log.Info().
		Int64("migrated", stats.Migrated).
		Int64("skipped", stats.Skipped).
		Int64("errors", stats.Errors).
		Msg("encryption migration: finished")

	if err != nil {
		return err
	}
	if stats.Errors > 0 {
		return fmt.Errorf("encryption migration completed with %d row-level errors — check logs", stats.Errors)
	}
	return nil
}
