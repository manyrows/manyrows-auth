package api

import "github.com/gofrs/uuid/v5"

// authenticatorNameForAAGUID returns a human-readable name for known
// authenticator AAGUIDs. Returns empty string for unknown AAGUIDs — the
// caller falls back to the user-supplied name or "Unnamed".
//
// The list below is intentionally conservative — only AAGUIDs sourced from
// the public FIDO Metadata Service or the authenticator vendor's own
// documentation are included. To add more without growing this file,
// download the MDS BLOB at startup and merge entries; for now, manual
// curation is fine because new authenticator models are rare.
//
// Known unmapped AAGUIDs in the wild (we'll see them as raw UUIDs in the
// admin UI) are a useful signal for what to add next.
func authenticatorNameForAAGUID(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return aaguidNames[id.String()]
}

var aaguidNames = map[string]string{
	// Apple — Touch ID / Face ID (iCloud Keychain syncs across devices)
	"f24a8e70-d0d3-f82c-2937-32523cc4de5a": "Apple Passkey",

	// Chrome on macOS — uses the keychain via a per-browser AAGUID
	"adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome (macOS)",

	// Google Password Manager (cross-platform sync via Google account)
	"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",

	// Android — platform key store on Android devices (per-device, no sync)
	"b93fd961-f2e6-462f-b122-82002247de78": "Android",

	// Microsoft Windows Hello (platform authenticator, TPM-backed when available)
	"08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
	"9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello (TPM)",
	"6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello (Hardware)",

	// 1Password
	"bada5566-a7aa-401f-bd96-45619a55120d": "1Password",

	// Bitwarden
	"d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",

	// Yubico — common production keys, AAGUIDs from FIDO MDS
	"f8a011f3-8c0a-4d15-8006-17111f9edc7d": "YubiKey 5 Series",
	"cb69481e-8ff7-4039-93ec-0a2729a154a8": "YubiKey 5 NFC (FIPS)",
	"73bb0cd4-e502-49b8-9c6f-b59445bf720b": "YubiKey 5 NFC",
	"85203421-48f9-4355-9bc8-8a53846e5083": "YubiKey 5C NFC",
	"c1f9a0bc-1dd2-404a-b27f-8e29047a43fd": "YubiKey 5 Bio Series",
	"a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa": "Security Key by Yubico",
}
