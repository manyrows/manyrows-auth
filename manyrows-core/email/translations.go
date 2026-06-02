package email

import (
	"strings"
	"sync/atomic"
)

// SupportedLanguages is the list of supported language codes for i18n.
// Kept in sync with api.SupportedLanguages and the UI i18n locales.
var SupportedLanguages = []string{"en", "ko"}

// brandName is the operator-facing project name that gets substituted for
// the `{brand}` placeholder in translations. Defaults to "ManyRows" until
// the host application calls SetBrand at startup (typically reading
// MANYROWS_BRAND_NAME via config). Stored in an atomic.Value so changes
// after init are race-free, though in practice it's set once at boot.
var brandName atomic.Value

func init() {
	brandName.Store("ManyRows")
}

// SetBrand replaces the brand name substituted into admin-facing email
// subjects and bodies. Empty input is ignored (keeps the prior value)
// so an unset env var doesn't blank out the brand mid-flight.
func SetBrand(name string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	brandName.Store(name)
}

// Brand returns the currently-configured brand name.
func Brand() string {
	v, _ := brandName.Load().(string)
	if v == "" {
		return "ManyRows"
	}
	return v
}

// translations holds all email template strings keyed by language and
// message key. `{brand}` is substituted with the operator-configured
// brand name (see SetBrand / MANYROWS_BRAND_NAME) at T() time, so the
// project name in admin-facing emails reflects whoever's running the
// install — not whoever wrote the code.
var translations = map[string]map[string]string{
	"en": {
		// Admin registration
		"admin.register.subject": "Your {brand} magic link",
		"admin.register.body":    "Hi,\n\nUse this magic link to finish registering your {brand} account:\n\n%s\n\nIf you didn't request this, you can ignore this email.\n",

		// Admin login
		"admin.login.subject": "Your {brand} sign-in link",
		"admin.login.body":    "Hi,\n\nUse this magic link to sign in to {brand}:\n\n%s\n\nIf you didn't request this, you can ignore this email.\n",

		// Workspace login
		"workspace.login.subject": "Your %s sign-in link",
		"workspace.login.body":    "Hi,\n\nUse this magic link to sign in to %s:\n\n%s\n\nOrganization: %s\n\nIf you didn't request this, you can ignore this email.\n",

		// Workspace OTP
		"workspace.otp.subject": "Your %s login code",
		"workspace.otp.body":    "Your login code for %s is:\n\n%s\n\nThis code expires in 10 minutes.\nIf you didn't request this, you can ignore this email.",

		// App magic link (end-user sign-in via one-click link)
		"apps.magicLink.subject": "Your %s sign-in link",
		"apps.magicLink.body":    "Hi,\n\nUse this link to sign in to %s:\n\n%s\n\nThis link expires in 15 minutes and can be used once.\nIf you didn't request this, you can ignore this email.\n",

		// Admin email validation
		"admin.validation.subject": "Your {brand} verification code",
		"admin.validation.body":    "Your verification code is:\n\n%s\n\nThis code expires in 15 minutes.\nIf you didn't request this, you can ignore this email.",

		// Admin password reset
		"admin.password_reset.subject": "Your {brand} password reset code",
		"admin.password_reset.body":    "Hi,\n\nUse this code to reset your {brand} password:\n\n%s\n\nThis code expires in 15 minutes.\nIf you didn't request this, you can ignore this email.\n",

		// Workspace password reset
		"workspace.password_reset.subject": "Password reset code for %s",
		"workspace.password_reset.body":    "Hi,\n\nUse this code to reset your password for %s:\n\n%s\n\nThis code expires in 15 minutes.\nIf you didn't request this, you can ignore this email.\n",

		// Email change (admin)
		"email_change.subject": "Verify your new {brand} email address",
		"email_change.body":    "Hi,\n\nYou requested to change your {brand} account email to this address.\n\nYour verification code is:\n\n%s\n\nThis code expires in 15 minutes.\nIf you didn't request this, you can ignore this email.\n",

		// Email change (workspace/app user)
		"workspace.email_change.subject": "Your email change code for %s",
		"workspace.email_change.body":    "Your email change verification code for %s is:\n\n%s\n\nThis code expires in 15 minutes.\nIf you didn't request this, you can ignore this email.",

		// Email change — notification sent to the OLD address after a
		// successful swap. Lets an account-takeover victim notice the
		// change before the attacker can pivot deeper. Doesn't contain
		// the new address — that would help the attacker confirm
		// where the account moved.
		"workspace.email_change.notice.subject": "Your %s email address was changed",
		"workspace.email_change.notice.body":    "The email address on your %s account was just changed.\n\nIf this was you, no action is needed.\n\nIf you didn't do this, contact the workspace administrator immediately — your account may have been taken over.",
		"email_change.notice.subject":           "Your {brand} email address was changed",
		"email_change.notice.body":              "The email address on your {brand} account was just changed.\n\nIf this was you, no action is needed.\n\nIf you didn't do this, reply to this email and we'll help you recover access.",

		// Team invite
		"team_invite.subject": "You've been invited to %s on {brand}",
		"team_invite.body":    "Hi,\n\n%s has invited you to join \"%s\" as an admin on {brand}.\n\nClick the link below to accept the invitation and create your account:\n\n%s\n\nThis link expires in 7 days.\nIf you didn't expect this, you can ignore this email.\n",

		// User invite (app user)
		"user_invite.subject": "You've been added to %s",
		"user_invite.body":    "Hi,\n\nYou've been added to %s.\n\nTo get started, visit the app and sign in:\n\n%s\n\nIf you don't have a password yet, click \"Forgot password\" on the sign-in page to set one up.\n",
	},
}

// T returns the translation for the given language and key, with the
// `{brand}` placeholder substituted for the operator-configured brand
// name. Falls back to English if the language or key is not found.
func T(lang, key string) string {
	if lang == "" {
		lang = "en"
	}

	var val string
	if langMap, ok := translations[lang]; ok {
		if v, ok := langMap[key]; ok {
			val = v
		}
	}
	if val == "" {
		if langMap, ok := translations["en"]; ok {
			if v, ok := langMap[key]; ok {
				val = v
			}
		}
	}
	if val == "" {
		return key
	}

	if strings.Contains(val, "{brand}") {
		val = strings.ReplaceAll(val, "{brand}", Brand())
	}
	return val
}
