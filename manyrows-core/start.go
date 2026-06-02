package main

import (
	"context"
	"fmt"
	"os"

	"manyrows-core/app"
	"manyrows-core/config"
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
	fmt.Fprintln(os.Stderr, "  web help                     print this message")
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
