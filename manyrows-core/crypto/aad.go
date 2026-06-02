package crypto

import "github.com/gofrs/uuid/v5"

// AAD builds an "additional authenticated data" string for AAD-bound
// GCM encryption (v0x03 ciphertexts). The format binds ciphertext to
// the specific row context, preventing a DB-write attacker from
// shuffling encrypted blobs between rows of the same column.
//
// Format: "<table>:<column>:<id>"
//
// Use this helper at both encrypt and decrypt sites for the same row;
// any drift between the two breaks GCM authentication and the read
// fails with a generic auth error.
func AAD(table, column string, id uuid.UUID) []byte {
	return []byte(table + ":" + column + ":" + id.String())
}
