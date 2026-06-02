package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"manyrows-core/config"
	"manyrows-core/crypto"

	"github.com/rs/zerolog/log"
)

// secretsStore is the narrow surface bootstrapSecrets needs from the
// repo — small enough to fake in unit tests without a DB. Includes
// the four methods the encrypting wrapper composes over, so Phase 2
// (post-encryption_key) can run with transparent at-rest encryption.
type secretsStore interface {
	GetSystemSecret(ctx context.Context, name string) (string, error)
	PutSystemSecret(ctx context.Context, name, value string) (string, error)
	UpsertSystemSecret(ctx context.Context, name, value string) error
	DeleteSystemSecret(ctx context.Context, name string) error
}

// bootstrapSecrets fills in any process secrets the operator hasn't
// already set in the environment. On first boot, this means
// generating cryptographically-random values for the HMAC keys,
// encryption key, and OTP pepper; on subsequent boots it reads them
// back from system_secrets so the same keys are reused.
//
// Env vars always win when set, so an operator who prefers
// config-as-code (k8s/Docker secrets, etc.) doesn't change a
// thing. The DB-backed path exists so a fresh self-hosted install
// can run with nothing but DATABASE_URL.
//
// Side effect: when a value is loaded from the DB or generated here,
// it's exported into the process env via os.Setenv before any
// downstream service reads its config. That keeps the existing
// config.GetXxx getters dumb (env-only) and avoids threading a
// "secrets provider" abstraction through every constructor.
//
// "Env wins" applies cleanly to HMAC keys and MANYROWS_OTP_PEPPER —
// those can be rotated by editing the env var, since they're only
// used to hash incoming material (existing sessions / OTPs become
// invalid, nothing becomes *unrecoverable*).
//
// ENCRYPTION_KEY is the exception: every encrypted column in every
// other table is bound to it, and a fresh value can't decrypt the
// existing data. We catch the most common footgun (operator sets
// MANYROWS_ENCRYPTION_KEY to a value that doesn't match the one
// already in system_secrets) and refuse to boot. The documented
// rotation path is to set MANYROWS_PREVIOUS_ENCRYPTION_KEYS=<old>
// alongside the new key and run `./web migrate-encryption`; that
// explicit signal disables the guard.
//
// At-rest encryption: encryption_key itself must stay plaintext in
// system_secrets (chicken and egg — nothing else could decrypt it on
// boot). Every other managed secret is encrypted at rest under the
// install's encryption_key, transparent to callers via the
// EncryptingSystemSecretsStore wrapper. Legacy plaintext rows from
// pre-encryption deploys decode as-is on first read and are rewritten
// encrypted in place; subsequent boots see the modern form.
//
// CRITICAL: the encryption key, once written to system_secrets, must
// never be regenerated — every encrypted column in every other table
// is bound to it. The repo layer's ON CONFLICT DO NOTHING is the
// only line of defence; never DELETE from system_secrets at runtime.
func bootstrapSecrets(ctx context.Context, store secretsStore, envPrefix string) error {
	// Phase 1: bootstrap encryption_key. This row stays plaintext in
	// system_secrets because the encryptor is built from it — encrypting
	// it would prevent boot. The guard below also still has to read raw.
	if err := bootstrapEncryptionKey(ctx, store, envPrefix); err != nil {
		return err
	}

	// Phase 2: with encryption_key now resolved into MANYROWS_ENCRYPTION_KEY
	// (either by env-win or by Phase 1's read-or-generate), build an
	// encryptor and a wrapping store that encrypts every other managed
	// secret transparently. Legacy plaintext rows from older deploys are
	// re-stored encrypted on first read by the wrapper.
	encCfg := config.NewConfig(envPrefix)
	if _, err := encCfg.GetEncryptionKey(); err != nil {
		return fmt.Errorf("bootstrap: read encryption key for phase 2: %w", err)
	}
	encryptor := crypto.NewMySecretEncryptor(encCfg)
	secure := crypto.NewEncryptingSystemSecretsStore(store, encryptor)

	managed := []struct {
		envName    string
		secretName string
		generate   func() (string, error)
	}{
		{
			envName:    envPrefix + "SESSION_AUTH_KEY",
			secretName: "session_auth_key",
			generate:   func() (string, error) { return randomHex(64) }, // 128 hex chars; getter slices [:64]
		},
		{
			envName:    envPrefix + "SESSION_SECRET_KEY",
			secretName: "session_secret_key",
			generate:   func() (string, error) { return randomHex(32) }, // 64 hex chars; getter slices [:32]
		},
		{
			envName:    envPrefix + "OTP_PEPPER",
			secretName: "otp_pepper",
			generate:   func() (string, error) { return randomHex(32) },
		},
	}

	for _, m := range managed {
		envVal := os.Getenv(m.envName)
		if envVal != "" {
			// Env wins. Don't read or write the DB row — for HMAC keys
			// and the OTP pepper the operator can rotate freely (worst
			// case: existing sessions / OTPs invalidate).
			continue
		}
		stored, err := secure.GetSystemSecret(ctx, m.secretName)
		if err != nil {
			return fmt.Errorf("read system secret %s: %w", m.secretName, err)
		}
		if stored == "" {
			gen, err := m.generate()
			if err != nil {
				return fmt.Errorf("generate %s: %w", m.secretName, err)
			}
			stored, err = secure.PutSystemSecret(ctx, m.secretName, gen)
			if err != nil {
				return fmt.Errorf("persist %s: %w", m.secretName, err)
			}
			log.Info().Str("secret", m.secretName).Str("env", m.envName).Msg("bootstrap: generated and stored new secret")
		} else {
			log.Debug().Str("secret", m.secretName).Str("env", m.envName).Msg("bootstrap: loaded existing secret from db")
		}
		if err := os.Setenv(m.envName, stored); err != nil {
			return fmt.Errorf("setenv %s: %w", m.envName, err)
		}
	}
	return nil
}

// bootstrapEncryptionKey handles the encryption_key row specifically.
// It MUST stay plaintext in system_secrets (it's the master KEK; nothing
// else could decrypt it on boot), and the mismatch guard has to run
// before the rest of bootstrap so a footgun ENCRYPTION_KEY can't quietly
// corrupt new writes against an existing-data deploy.
func bootstrapEncryptionKey(ctx context.Context, store secretsStore, envPrefix string) error {
	const secretName = "encryption_key"
	envName := envPrefix + "ENCRYPTION_KEY"
	envVal := os.Getenv(envName)

	// Mismatch guard. Read stored value first; if env disagrees with
	// what's in system_secrets and the operator hasn't signalled a
	// rotation via PREVIOUS_ENCRYPTION_KEYS, refuse to boot rather
	// than silently re-encrypt new rows under a key that can't read
	// the old ones.
	if envVal != "" {
		stored, err := store.GetSystemSecret(ctx, secretName)
		if err != nil {
			return fmt.Errorf("read system secret %s: %w", secretName, err)
		}
		if stored != "" && stored != envVal {
			if os.Getenv(envPrefix+"PREVIOUS_ENCRYPTION_KEYS") == "" {
				return fmt.Errorf(
					"%s does not match the key already stored in system_secrets, "+
						"and %sPREVIOUS_ENCRYPTION_KEYS is unset. Existing encrypted "+
						"columns were written under the stored key; booting with a "+
						"different one will silently corrupt new writes. To rotate, "+
						"set %sPREVIOUS_ENCRYPTION_KEYS=<old key> and run "+
						"`./web migrate-encryption` before deploying the new key alone. "+
						"To use the stored key, unset %s and let bootstrap reload it.",
					envName, envPrefix, envPrefix, envName,
				)
			}
			log.Warn().
				Str("secret", secretName).
				Msg("bootstrap: ENCRYPTION_KEY differs from stored value; PREVIOUS_ENCRYPTION_KEYS is set, assuming rotation in progress")
		}
		// Env wins; nothing to write.
		return nil
	}

	// No env override. Reuse stored if present; otherwise generate
	// the install's first-and-only encryption key.
	stored, err := store.GetSystemSecret(ctx, secretName)
	if err != nil {
		return fmt.Errorf("read system secret %s: %w", secretName, err)
	}
	if stored == "" {
		b := make([]byte, 32) // AES-256
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("generate %s: %w", secretName, err)
		}
		gen := "base64:" + base64.StdEncoding.EncodeToString(b)
		stored, err = store.PutSystemSecret(ctx, secretName, gen)
		if err != nil {
			return fmt.Errorf("persist %s: %w", secretName, err)
		}
		log.Info().Str("secret", secretName).Str("env", envName).Msg("bootstrap: generated and stored new secret")
	} else {
		log.Debug().Str("secret", secretName).Str("env", envName).Msg("bootstrap: loaded existing secret from db")
	}
	if err := os.Setenv(envName, stored); err != nil {
		return fmt.Errorf("setenv %s: %w", envName, err)
	}
	return nil
}

func randomHex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
