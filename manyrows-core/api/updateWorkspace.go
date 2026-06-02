package api

import (
	"encoding/json"
	"errors"
	"manyrows-core/core/repo"
	"net/http"
	"strings"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/publicsuffix"
)

const (
	maxWorkspaceName = 80
	maxWorkspaceSlug = 80
)

var (
	ErrSlugConflict = errors.New("slug conflict")
)

type updateWorkspaceRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// create request accepts name+slug from UI
type createWorkspaceRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// ----------------------------
// Slug rules (workspace)
// ----------------------------
//
// Goal: strict, predictable, URL-safe slugs.
// - lowercase a-z
// - digits 0-9
// - hyphen
// - must start/end with [a-z0-9]
// - no consecutive hyphens
// - length <= maxWorkspaceSlug
//
// We normalize by trimming + lowercasing. We do NOT "auto-fix" other characters;
// instead we reject with 400 so the UI can show a precise error.
func normalizeWorkspaceSlug(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func validateWorkspaceSlug(slug string) error {
	if slug == "" {
		return errors.New("slug is required")
	}
	if len(slug) > maxWorkspaceSlug {
		return errors.New("slug is too long")
	}

	// first/last must be alnum
	if !isLowerAlphaNum(slug[0]) {
		return errors.New("slug must start with a letter or number")
	}
	if !isLowerAlphaNum(slug[len(slug)-1]) {
		return errors.New("slug must end with a letter or number")
	}

	prevHyphen := false
	for i := 0; i < len(slug); i++ {
		ch := slug[i]

		if ch == '-' {
			if prevHyphen {
				return errors.New("slug cannot contain consecutive hyphens")
			}
			prevHyphen = true
			continue
		}
		prevHyphen = false

		if isLowerAlphaNum(ch) {
			continue
		}
		return errors.New("slug may only contain lowercase letters, numbers, and hyphens")
	}

	return nil
}

func isLowerAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// ----------------------------
// Handlers
// ----------------------------

func (handler *RequestHandler) UpdateWorkspace(w http.ResponseWriter, r *http.Request) {
	acc, ok := core.AdminAccountFromContext(r.Context())
	if !ok || acc == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	workspaceID, err := utils.GetPathUUID("workspaceId", r)
	if workspaceID == uuid.Nil || err != nil {
		WriteError(w, r, "error.missingWorkspaceId", http.StatusBadRequest)
		return
	}

	// Decode body
	var req updateWorkspaceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	// Validate
	name := strings.TrimSpace(req.Name)
	slug := normalizeWorkspaceSlug(req.Slug)

	if name == "" {
		WriteError(w, r, "error.nameRequired", http.StatusBadRequest)
		return
	}
	if len(name) > maxWorkspaceName {
		WriteErrorf(w, r, "error.fieldTooLong", http.StatusBadRequest, "Name", maxWorkspaceName)
		return
	}

	if err := validateWorkspaceSlug(slug); err != nil {
		WriteError(w, r, "error.slugInvalid", http.StatusBadRequest)
		return
	}

	bySlug, _, err := handler.repo.GetWorkspaceBySlug(r.Context(), slug)
	if err != nil {
		log.Err(err).Msg("Could not check slug uniqueness")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if bySlug != nil && bySlug.ID != workspaceID {
		WriteError(w, r, "error.conflict", http.StatusConflict)
		return
	}

	ws, ok, err := handler.GetWorkspaceAsAdmin(r.Context(), workspaceID, acc)
	if err != nil {
		log.Err(err).Msg("Could not get workspace")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !ok {
		WriteError(w, r, "error.workspaceNotFound", http.StatusForbidden)
		return
	}

	// Changing the slug rewrites the public API path segment (/x/{slug}/...),
	// breaking every client + S2S integration pointing at the old slug — a
	// blast radius beyond day-to-day admin. Restrict slug changes to owners;
	// non-owner admins can still rename the workspace.
	if slug != ws.Slug && !handler.requireOwner(w, r) {
		return
	}

	ws.Name = name
	ws.Slug = slug

	err = handler.repo.UpdateWorkspace(r.Context(), ws)
	if err != nil {
		log.Err(err).Msg("Could not update workspace")
		switch {
		case errors.Is(err, repo.ErrNotFound):
			WriteError(w, r, "error.workspaceNotFound", http.StatusNotFound)
			return
		case errors.Is(err, ErrSlugConflict):
			WriteError(w, r, "error.conflict", http.StatusConflict)
			return
		default:
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
	}

	utils.WriteJson(w, ws)
}

// ----------------------------
// Cookie domain
// ----------------------------

type updateWorkspaceCookieDomainRequest struct {
	CookieDomain *string `json:"cookieDomain"`
}

// HandleUpdateWorkspaceCookieDomain sets the workspace-level session-
// cookie Domain attribute. Empty string clears it; the browser then
// scopes the cookie to the exact host that set it. Format must be
// either empty, a parent-domain form starting with "." (e.g.
// ".example.com"), or a bare host. Public-suffix values like
// ".github.io" are rejected because cookies set on a public suffix
// would scope across unrelated tenants.
func (handler *RequestHandler) HandleUpdateWorkspaceCookieDomain(w http.ResponseWriter, r *http.Request) {
	acc, ok := core.AdminAccountFromContext(r.Context())
	if !ok || acc == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	// Cookie-domain scopes session cookies across hosts — a security-relevant
	// setting with cross-app blast radius. Owner-only.
	if !handler.requireOwner(w, r) {
		return
	}

	workspaceID, err := utils.GetPathUUID("workspaceId", r)
	if workspaceID == uuid.Nil || err != nil {
		WriteError(w, r, "error.missingWorkspaceId", http.StatusBadRequest)
		return
	}

	var req updateWorkspaceCookieDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	var stored *string
	if req.CookieDomain != nil {
		v := strings.TrimSpace(*req.CookieDomain)
		if v == "" {
			stored = nil
		} else {
			if err := validateCookieDomain(v); err != nil {
				WriteError(w, r, "error.invalidCookieDomain", http.StatusBadRequest)
				return
			}
			stored = &v
		}
	}

	if _, ok, err := handler.GetWorkspaceAsAdmin(r.Context(), workspaceID, acc); err != nil {
		log.Err(err).Msg("Could not load workspace for cookie-domain update")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	} else if !ok {
		WriteError(w, r, "error.workspaceNotFound", http.StatusForbidden)
		return
	}

	updated, err := handler.repo.UpdateWorkspaceCookieDomain(r.Context(), workspaceID, stored)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.workspaceNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to update workspace cookie domain")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, updated)
}

// validateCookieDomain checks that a candidate cookie Domain attribute
// is well-formed and doesn't scope across unrelated parties via a
// public suffix. Accepts both ".example.com" (recommended parent-
// domain form) and "example.com" (bare host).
//
// Setting a cookie domain to a public suffix (.co.uk, .github.io,
// .vercel.app, …) would let every other workspace hosted under that
// suffix read the session cookie. Browsers reject Set-Cookie for the
// PSL entries they ship with, but the PSL embedded in Chrome/Firefox
// lags reality — and a self-hosted install operating below browser-
// kernel level shouldn't rely on the client to enforce this. The
// authoritative source is the Mozilla Public Suffix List, which
// golang.org/x/net/publicsuffix tracks.
func validateCookieDomain(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	host := strings.ToLower(strings.TrimPrefix(v, "."))
	if host == "" || strings.Contains(host, " ") || strings.Contains(host, "/") {
		return errors.New("invalid cookie domain")
	}
	// publicsuffix.PublicSuffix returns the longest matching public
	// suffix of host. If host == suffix, host IS a public suffix
	// itself ("co.uk", "github.io", "co.jp", …) and unsafe to scope
	// a cookie to. The exact-equality test catches the multi-label
	// PSL entries the old hardcoded shortlist missed.
	suffix, _ := publicsuffix.PublicSuffix(host)
	if host == suffix {
		return errors.New("public-suffix cookie domain rejected")
	}
	return nil
}

// CreateWorkspace is disabled in the self-hosted shape — the single
// workspace is auto-created for the first admin (see adminAuth.go).
// The UI hides the "new workspace" affordance; this handler rejects
// any direct POST in case it's reached via a forged request.
func (handler *RequestHandler) CreateWorkspace(w http.ResponseWriter, r *http.Request) {
	if _, ok := core.AdminAccountFromContext(r.Context()); !ok {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}
	WriteError(w, r, "error.forbidden", http.StatusForbidden)
}
