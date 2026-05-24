// Package passwordhash is the single hashing surface every
// password-handling code path in manyrows-core goes through. It
// always uses argon2id (OWASP 2026 default — memory-hard, GPU-
// resistant) encoded as a standard PHC string:
//
//	$argon2id$v=19$m=65536,t=3,p=1$<b64-nopad salt>$<b64-nopad hash>
//
// The PHC encoding carries the params with each hash, so a future
// parameter bump won't break verification of older hashes.
package passwordhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. OWASP 2026 floor: 64 MiB / 3 iters / 1
// thread, 16-byte salt, 32-byte tag. Costs ~50ms on a modern
// server CPU and is meaningfully expensive on a GPU.
//
// Don't decrease memory or iters without an offline migration —
// existing hashes carry their params on disk and would still
// verify, but new hashes would silently weaken.
const (
	argonMemory      uint32 = 64 * 1024
	argonIterations  uint32 = 3
	argonParallelism uint8  = 1
	argonSaltLen     uint32 = 16
	argonKeyLen      uint32 = 32
)

const argonPrefix = "$argon2id$"

// b64 is the no-padding base64 the PHC format uses.
var b64 = base64.RawStdEncoding

// Hash produces an argon2id PHC string suitable for storing in
// users.password_hash.
func Hash(password string) (string, error) {
	if password == "" {
		return "", errors.New("passwordhash: empty password")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("passwordhash: salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonIterations, argonParallelism,
		b64.EncodeToString(salt), b64.EncodeToString(key),
	), nil
}

// Verify checks `password` against `encoded`.
//
// Returns:
//   - ok  : password matched
//   - err : encoding malformed (does NOT include "wrong password" —
//     that's ok=false, err=nil)
//
// On err != nil, ok is false.
func Verify(encoded, password string) (ok bool, err error) {
	if !strings.HasPrefix(encoded, argonPrefix) {
		return false, fmt.Errorf("passwordhash: unrecognised hash format")
	}
	parts := strings.Split(encoded, "$")
	// "$argon2id$v=19$m=...,t=...,p=...$salt$hash" splits to
	// ["", "argon2id", "v=19", "m=...,t=...,p=...", "salt", "hash"]
	if len(parts) != 6 {
		return false, fmt.Errorf("passwordhash: argon2 wrong segment count")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("passwordhash: argon2 version: %w", err)
	}
	if version != argon2.Version {
		return false, fmt.Errorf("passwordhash: unsupported argon2 version %d", version)
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, fmt.Errorf("passwordhash: argon2 params: %w", err)
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("passwordhash: argon2 salt: %w", err)
	}
	stored, err := b64.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("passwordhash: argon2 hash: %w", err)
	}
	computed := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(stored)))
	if subtle.ConstantTimeCompare(stored, computed) != 1 {
		return false, nil
	}
	return true, nil
}

// DummyVerify burns ~one verify's worth of CPU against a throwaway
// salt/password. Use it on the no-user / no-password branch of a
// login flow so the response time matches the real-user branch and
// doesn't leak account existence.
var _dummySalt = []byte("dummysaltforpwhash") // fixed; doesn't matter, the goal is to spend CPU

func DummyVerify(password string) {
	_ = argon2.IDKey([]byte(password), _dummySalt, argonIterations, argonMemory, argonParallelism, argonKeyLen)
}
