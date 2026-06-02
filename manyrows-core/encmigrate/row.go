package encmigrate

import (
	"manyrows-core/crypto"
)

// migrationAction is what migrateRow decided to do with a single
// encrypted row. The walker uses this to bump the matching stats
// counter and decide whether to issue an UPDATE.
type migrationAction int

const (
	// actionSkipped: row is already in the active-key canonical
	// format. No UPDATE needed.
	actionSkipped migrationAction = iota

	// actionMigrated: row was decrypted (either v0x03 legacy or
	// v0x04 under a previous key) and re-encrypted under the
	// active key. Caller writes newCt back to the DB.
	actionMigrated

	// actionError: row could not be decrypted with any known key,
	// or re-encrypt failed. Caller logs and leaves the row
	// unchanged — never clobber a row we can't read back.
	actionError
)

// migrateRow decides what to do with a single encrypted-column row
// and computes the new ciphertext when a rewrite is needed.
//
// Pure: no DB, no I/O. The walker calls this once per row and either
// UPDATEs (on actionMigrated) or moves on (on actionSkipped /
// actionError). Extracted from migrateColumn so the security-critical
// "decrypt under any known key, re-encrypt under the active key
// while preserving plaintext byte-for-byte" logic is testable
// without spinning up a database.
//
// Invariants worth stating:
//   - actionError NEVER returns a non-nil newCt. The caller must not
//     write garbage back.
//   - actionSkipped NEVER returns a non-nil newCt. The on-disk bytes
//     are already correct.
//   - actionMigrated's newCt MUST decrypt back to the same plaintext
//     under the active key + the same AAD. This is the rotation
//     correctness property the walker exists to maintain.
func migrateRow(enc crypto.SecretEncryptor, data, aad []byte) (newCt []byte, action migrationAction, err error) {
	if enc.IsCanonical(data) {
		return nil, actionSkipped, nil
	}

	plain, err := enc.DecryptFromBytesWithAAD(data, aad)
	if err != nil {
		return nil, actionError, err
	}

	newCt, err = enc.EncryptToBytesWithAAD(plain, aad)
	if err != nil {
		return nil, actionError, err
	}
	return newCt, actionMigrated, nil
}
