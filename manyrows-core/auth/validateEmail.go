package auth

import (
	"manyrows-core/core/validation"
	"net/mail"
	"strings"
	"unicode/utf8"
)

// ValidateEmail normalizes and validates an email address.
// Returns the normalized email and a validation result.
func ValidateEmail(raw string) (string, *validation.Result) {
	email := strings.TrimSpace(strings.ToLower(raw))

	if email == "" {
		return "", validation.NewIssue("email", "required", "email is required")
	}

	if !utf8.ValidString(email) || len(email) > 254 {
		return "", validation.NewIssue("email", "invalid", "email is invalid")
	}

	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return "", validation.NewIssue("email", "invalid", "email is invalid")
	}

	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return "", validation.NewIssue("email", "invalid", "email is invalid")
	}

	local := email[:at]
	domain := email[at+1:]

	if len(local) > 64 {
		return "", validation.NewIssue("email", "invalid", "email is invalid")
	}

	if !strings.Contains(domain, ".") {
		return "", validation.NewIssue("email", "invalid", "email domain is invalid")
	}

	labels := strings.Split(domain, ".")
	for _, lab := range labels {
		if lab == "" {
			return "", validation.NewIssue("email", "invalid", "email domain is invalid")
		}
		if lab[0] == '-' || lab[len(lab)-1] == '-' {
			return "", validation.NewIssue("email", "invalid", "email domain is invalid")
		}
	}

	return email, &validation.Result{}
}
