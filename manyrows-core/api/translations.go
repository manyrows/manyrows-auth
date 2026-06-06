package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"manyrows-core/core/validation"
	"manyrows-core/utils"
)

// apiTranslations holds all API error message translations keyed by language and message key.
var apiTranslations = map[string]map[string]string{
	"en": {
		// Generic errors
		"error.unauthorized":    "Unauthorized",
		"error.forbidden":       "Forbidden",
		"error.notFound":        "Not found",
		"error.badRequest":      "Bad request",
		"error.internalError":   "Internal server error",
		"error.tooManyRequests": "Too many requests. Please wait and try again.",
		"error.limitReached":    "You've reached the maximum number of %s (limit %d).",
		"error.invalidJson":     "Invalid JSON",
		// Admin handler error keys (previously undefined → rendered as the raw key).
		"error.invalidRPID":                 "Invalid relying-party ID: %s",
		"error.invalidAuthDomain":           "Invalid authentication domain",
		"error.invalidCookieDomain":         "Invalid cookie domain",
		"error.invalidTransportMode":        "Invalid session transport mode",
		"error.invalidSameSiteMode":         "Invalid SameSite mode",
		"error.strictRequiresNoMagicLinks":  "Strict transport requires magic-link sign-in to be disabled",
		"error.strictRequiresNoOAuth":       "Strict transport requires OAuth sign-in to be disabled",
		"error.userPoolNotFound":            "User pool not found",
		"error.userNotFound":                "User not found",
		"error.invalidInactiveDays":         "Invalid inactive-days value",
		"error.invalidRoleFilter":           "Invalid role filter",
		"error.originAlreadyExists":         "That origin is already allowed",
		"error.invalidMetric":               "Invalid metric",
		"error.invalidRequest":              "Invalid request",
		"error.googleClientSecretRequired":  "A Google client secret is required",
		"error.oidcRedirectUrisRequired":    "At least one OIDC redirect URI is required",
		"error.oidcRequiresCookieTransport": "OIDC requires cookie session transport",
		"error.qrSignInRequiresAppURL":      "QR sign-in requires the app URL to be configured",
		"error.invalidRole":                 "Invalid role",
		// Client auth-flow error keys (passkey / TOTP / captcha) — also previously undefined.
		"error.captchaFailed":             "Captcha verification failed",
		"error.identityConflict":          "That identity is already linked to another account",
		"error.invalidDPoPProof":          "Invalid DPoP proof",
		"error.pairingNotFound":           "Pairing not found or expired",
		"error.passkeyAlreadyRegistered":  "This passkey is already registered",
		"error.passkeyBeginFailed":        "Could not start passkey registration",
		"error.passkeyChallengeInvalid":   "Invalid or expired passkey challenge",
		"error.passkeyCloneSuspected":     "This passkey could not be verified and was rejected",
		"error.passkeyLimitReached":       "You've reached the maximum number of passkeys",
		"error.passkeyResponseInvalid":    "Invalid passkey response",
		"error.passkeyUVRequired":         "Passkey user verification is required",
		"error.passkeyVerifyFailed":       "Passkey verification failed",
		"error.passkeysDisabled":          "Passkeys are not enabled for this app",
		"error.passwordSetRequiresOTP":    "Setting a password requires a verification code",
		"error.reauthRequired":            "Please re-authenticate to continue",
		"error.registrationDisabled":      "Registration is disabled",
		"error.totpSetupChallengeExpired": "Your two-factor setup session expired; please start again",
		"error.totpSetupChallengeInvalid": "Invalid two-factor setup session",
		"error.invalidCode":               "Invalid code",
		"error.currentPasswordRequired":   "Current password is required",
		"error.invalidCurrentPassword":    "Current password is incorrect",
		"error.invalidTOTPCode":           "Invalid code. Please try again.",
		"error.totpAlreadyEnabled":        "Two-factor authentication is already enabled",
		"error.totpNotSetUp":              "Two-factor authentication has not been set up yet",
		"error.totpNotEnabled":            "Two-factor authentication is not enabled",
		"error.totpChallengeExpired":      "Verification expired. Please log in again.",

		// Validation errors
		"error.nameRequired":           "Name is required",
		"error.nameEmpty":              "Name cannot be empty",
		"error.emailRequired":          "Email is required",
		"error.emailInvalid":           "Invalid email address",
		"error.emailTaken":             "Email is already in use",
		"error.emailAlreadyRegistered": "This email is already registered. Sign in instead.",
		"error.passwordRequired":       "Password is required",
		"error.passwordTooShort":       "Password must be at least %[1]d characters",
		"error.passwordTooWeak":        "Password is too weak. Pick something less guessable (avoid common words, keyboard patterns, and personal info).",
		"error.passwordIncorrect":      "Incorrect password",
		"error.slugRequired":           "Slug is required",
		"error.slugEmpty":              "Slug cannot be empty",
		"error.slugInvalid":            "Invalid slug format",
		"error.statusRequired":         "Status is required",
		"error.statusEmpty":            "Status cannot be empty",
		"error.statusInvalid":          "Invalid status",
		"error.languageInvalid":        "Unsupported language",
		"error.fieldTooLong":           "%[1]s must be at most %[2]d characters",
		"error.fieldTooShort":          "%[1]s must be at least %[2]d characters",
		"error.fieldLength":            "%[1]s must be between %[2]d and %[3]d characters",

		// Resource errors
		"error.accountNotFound":       "Account not found",
		"error.workspaceNotFound":     "Workspace not found",
		"error.projectNotFound":       "Project not found",
		"error.projectDisabled":       "Project is disabled",
		"error.projectNotInWorkspace": "Project not in workspace",
		"error.roleNotFound":          "Role not found",
		"error.permissionNotFound":    "Permission not found",
		"error.apiKeyNotFound":        "API key not found",
		"error.sessionNotFound":       "Session not found",
		"error.appNotFound":           "App not found",
		"error.appDisabled":           "App is disabled",
		"error.invalidStatus":         "Invalid status (expected \"active\" or \"disabled\")",
		"error.permissionsInvalid":    "One or more permissions are invalid",
		"error.invalidEmail":          "Invalid email address",
		"error.batchTooLarge":         "Batch too large (max %d users per request)",
		"error.appUrlRequired":        "An App URL must be configured to send invite emails",

		// ID errors
		"error.missingProjectId":     "Missing project ID",
		"error.missingWorkspaceId":   "Missing workspace ID",
		"error.missingWorkspaceSlug": "Missing workspace slug",
		"error.missingAccountId":     "Missing account ID",
		"error.invalidProjectId":     "Invalid project ID",
		"error.invalidWorkspaceId":   "Invalid workspace ID",
		"error.invalidAccountId":     "Invalid account ID",
		"error.invalidPage":          "Invalid page",
		"error.invalidPageSize":      "Invalid page size",
		"error.invalidAppId":         "Invalid app ID",
		"error.invalidFeatureFlagId": "Invalid feature flag ID",
		"error.invalidConfigKeyId":   "Invalid config key ID",
		"error.invalidRoleId":        "Invalid role ID",
		"error.invalidPermissionId":  "Invalid permission ID",
		"error.invalidApiKeyId":      "Invalid API key ID",
		"error.invalidUserId":        "Invalid user ID",

		// Auth errors
		"error.invalidCredentials": "Invalid email or password",
		"error.invalidToken":       "Invalid or expired token",
		"error.alreadyLoggedIn":    "Already logged in",
		"error.notLoggedIn":        "Not logged in",
		"error.emailNotVerified":   "Email not verified",
		"error.accountDisabled":    "Your account has been disabled",

		// Feature-specific errors
		"error.featureFlagNotFound":       "Feature flag not found",
		"error.configKeyNotFound":         "Config key not found",
		"error.configValueNotFound":       "Config value not found",
		"error.encryptionKeyNotFound":     "Encryption key not found",
		"error.keyInvalid":                "Invalid key format",
		"error.keyExists":                 "Key already exists",
		"error.conflict":                  "Resource conflict",
		"error.userNotSignedIn":           "That email isn't a registered user of this app yet — they must sign in once before being added.",
		"error.secretsNotSupportedViaAPI": "Secret config values must be set via the admin UI",

		// Workspace account errors
		"error.workspaceAccountNotFound": "Workspace account not found",
		"error.workspaceAccountExists":   "Workspace account already exists",

		// Auth method errors
		"error.noSignInMethodEnabled":           "At least one sign-in method must remain enabled. Turn on a sign-in method (email, Google, Apple, Microsoft, or GitHub) before disabling the others.",
		"error.authMethodDisabled":              "This sign-in method is not enabled for this app.",
		"error.magicLinkRequiresAppUrl":         "Magic-link sign-in requires the app to have an App URL configured.",
		"error.googleClientIdRequired":          "A Google OAuth Client ID is required to enable Google sign-in.",
		"error.appleConfigIncomplete":           "Configure all four Apple credential fields (Services ID, Team ID, Key ID, .p8 key) before enabling.",
		"error.appleKeyInvalid":                 "The Apple .p8 private key is not a valid PKCS8 EC key.",
		"error.appleNotConfigured":              "Apple sign-in is not configured for this app.",
		"error.microsoftConfigIncomplete":       "Configure both Microsoft Client ID and Client Secret before enabling.",
		"error.microsoftNotConfigured":          "Microsoft sign-in is not configured for this app.",
		"error.microsoftTenantInvalid":          "Microsoft tenant must be 'common', 'organizations', 'consumers', or a tenant UUID.",
		"error.microsoftEmailDomainNotVerified": "Sign-in is unavailable due to a configuration issue. Please contact the app administrator.",
		"error.githubConfigIncomplete":          "Configure both GitHub Client ID and Client Secret before enabling.",
		"error.githubNotConfigured":             "GitHub sign-in is not configured for this app.",
		"error.githubNoVerifiedEmail":           "Your GitHub account has no verified primary email. Verify a primary email in your GitHub settings and try again.",
		"error.googleOAuthNotConfigured":        "Google OAuth is not configured for this app.",
		"error.emailNotProvided":                "Sign-in provider did not return an email address.",
		"error.invalidOrigin":                   "The opener origin is not allowed for this app.",

		// Generic external IdP (OIDC / OAuth2) admin config errors
		"error.externalIdpInvalidSlug":          "Slug must be lowercase letters, numbers, and hyphens (starting with a letter or number).",
		"error.externalIdpDisplayNameRequired":  "Display name is required.",
		"error.externalIdpInvalidMode":          "Mode must be either OIDC or OAuth2.",
		"error.externalIdpClientIdRequired":     "Client ID is required.",
		"error.externalIdpClientSecretRequired": "Client secret is required.",
		"error.externalIdpIssuerRequired":       "An issuer URL is required for OIDC providers.",
		"error.externalIdpEndpointsRequired":    "Authorize, token, and userinfo URLs are all required for OAuth2 providers.",
		"error.externalIdpInsecureUrl":          "Provider URLs must use https.",
		"error.externalIdpSlugTaken":            "A provider with that slug already exists for this app.",

		// CORS/IP errors
		"error.corsOriginNotFound":    "CORS origin not found",
		"error.ipNotAllowed":          "IP address not allowed",
		"error.invalidOriginUrl":      "Invalid origin URL",
		"error.ipRangeRequired":       "IP range is required",
		"error.invalidIpRange":        "Invalid IP address or CIDR range",
		"error.ipRangeExists":         "IP range already exists",
		"error.messageRequired":       "Message is required",
		"error.messageTooLong":        "Message too long",
		"error.rolesInvalid":          "One or more roles are invalid",
		"error.appIdRequired":         "App ID is required",
		"error.originRequiresScheme":  "Origin must start with http:// or https://",
		"error.originRequiresHost":    "Origin must include a host",
		"error.originNoPath":          "Origin must not include a path",
		"error.originNoQueryFragment": "Origin must not include query or fragment",
		"error.originNoUserInfo":      "Origin must not include user info",
		"error.smtpTestFailed":        "SMTP test failed: %s",

		// Team errors
		"error.team.notFound":              "Account not found",
		"error.team.cannotRemoveSelf":      "You cannot remove yourself from the team",
		"error.team.cannotRemoveLastOwner": "Cannot remove the last owner",
		"error.team.alreadyInvited":        "An invitation has already been sent to this email",

		// Lockout errors
		"error.accountLocked": "Account is temporarily locked due to too many failed attempts. Please try again later.",
	},
}

// T returns the translated error message for the given language and key.
// Falls back to English if the language or key is not found.
func T(lang, key string) string {
	if lang == "" {
		lang = "en"
	}

	// Try the requested language
	if langMap, ok := apiTranslations[lang]; ok {
		if val, ok := langMap[key]; ok {
			return val
		}
	}

	// Fallback to English
	if langMap, ok := apiTranslations["en"]; ok {
		if val, ok := langMap[key]; ok {
			return val
		}
	}

	// Return the key itself as last resort
	return key
}

// Tf returns a translated message with format arguments.
// Use positional syntax %[1]s, %[2]d etc. in translations for language-specific word order.
func Tf(lang, key string, args ...any) string {
	template := T(lang, key)
	if len(args) == 0 {
		return template
	}
	return fmt.Sprintf(template, args...)
}

// GetLanguageFromRequest resolves the request's UI language from the
// Accept-Language header, restricted to the locales we actually ship. The
// admin UI sets this header from the active i18next locale, so error
// messages come back in the same language as the rest of the screen
// (works pre-auth on the login page too, where there's no account yet).
// Unknown or absent values fall back to English.
func GetLanguageFromRequest(r *http.Request) string {
	if r == nil {
		return "en"
	}
	// Browsers send tags in descending priority order; we ignore q-weights
	// since our supported set is tiny (en, ko) and take the first match.
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		tag := strings.ToLower(strings.TrimSpace(part))
		if i := strings.IndexByte(tag, ';'); i >= 0 {
			tag = tag[:i]
		}
		switch {
		case tag == "ko" || strings.HasPrefix(tag, "ko-"):
			return "ko"
		case tag == "en" || strings.HasPrefix(tag, "en-"):
			return "en"
		}
	}
	return "en"
}

// ErrorResponse is the standard error response format
type ErrorResponse struct {
	Error   string `json:"error"`   // Error code (e.g., "error.nameRequired")
	Message string `json:"message"` // Translated human-readable message
}

// WriteError writes a translated error response
func WriteError(w http.ResponseWriter, r *http.Request, code string, httpStatus int) {
	lang := GetLanguageFromRequest(r)
	message := T(lang, code)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(ErrorResponse{Error: code, Message: message})
}

// WriteRateLimitError writes a 429 response with a Retry-After header.
func WriteRateLimitError(w http.ResponseWriter, r *http.Request, retryAfterSeconds int) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
	WriteError(w, r, "error.tooManyRequests", http.StatusTooManyRequests)
}

// WriteErrorf writes a translated error response with format arguments.
// Use this for parameterized messages like "Password must be at least %d characters".
func WriteErrorf(w http.ResponseWriter, r *http.Request, code string, httpStatus int, args ...any) {
	lang := GetLanguageFromRequest(r)
	message := Tf(lang, code, args...)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(ErrorResponse{Error: code, Message: message})
}

// WriteErrorMsg writes an error response with a custom (non-translated) message.
func WriteErrorMsg(w http.ResponseWriter, _ *http.Request, message string, httpStatus int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(ErrorResponse{Error: "error.badRequest", Message: message})
}

// WriteValidationError writes a validation.Result as a JSON error response.
// Uses vr.Status if set, otherwise defaults to 400.
func WriteValidationError(w http.ResponseWriter, _ *http.Request, vr *validation.Result) {
	status := vr.Status
	if status == 0 {
		status = http.StatusBadRequest
	}
	utils.WriteJsonWithStatusCode(w, struct {
		Error  string             `json:"error"`
		Issues []validation.Issue `json:"issues"`
	}{
		Error:  "validation",
		Issues: vr.Issues,
	}, status)
}
