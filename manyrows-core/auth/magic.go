package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func (a *Service) NewMagicToken() (rawToken string, tokenHash string, err error) {
	// 32 bytes => 256-bit token
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("rand.Read: %w", err)
	}

	// URL-safe token (no padding) to put in links
	rawToken = base64.RawURLEncoding.EncodeToString(b)

	// Store only a hash in DB
	sum := sha256.Sum256([]byte(rawToken))
	tokenHash = hex.EncodeToString(sum[:])

	return rawToken, tokenHash, nil
}

func (a *Service) HashMagicToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}
