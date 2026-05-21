package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"manyrows-core/auth/oidc"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/crypto"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// =====================
// Admin: external IdP (generic OIDC / OAuth2) CRUD
// =====================
//
// REST sub-resource on an app, mirroring the webhooks CRUD shape:
//   GET    /products/{pid}/apps/{appId}/external-idps
//   POST   /products/{pid}/apps/{appId}/external-idps
//   POST   /products/{pid}/apps/{appId}/external-idps/validate-discovery
//   PUT    /products/{pid}/apps/{appId}/external-idps/{idpId}
//   DELETE /products/{pid}/apps/{appId}/external-idps/{idpId}

// slugPattern matches the external_idps.slug CHECK; validated up-front so
// a bad slug yields a clean 400 instead of a DB constraint error.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type externalIDPResponse struct {
	ID                   string `json:"id"`
	Slug                 string `json:"slug"`
	DisplayName          string `json:"displayName"`
	Enabled              bool   `json:"enabled"`
	Mode                 string `json:"mode"`
	IssuerURL            string `json:"issuerUrl,omitempty"`
	AuthorizeURL         string `json:"authorizeUrl,omitempty"`
	TokenURL             string `json:"tokenUrl,omitempty"`
	UserinfoURL          string `json:"userinfoUrl,omitempty"`
	JWKSURL              string `json:"jwksUrl,omitempty"`
	ClientID             string `json:"clientId"`
	HasClientSecret      bool   `json:"hasClientSecret"`
	Scopes               string `json:"scopes"`
	SubjectField         string `json:"subjectField"`
	EmailField           string `json:"emailField"`
	EmailVerifiedField   string `json:"emailVerifiedField,omitempty"`
	NameField            string `json:"nameField,omitempty"`
	ButtonIcon           string `json:"buttonIcon,omitempty"`
	TrustUnverifiedEmail bool   `json:"trustUnverifiedEmail"`
	CreatedAt            string `json:"createdAt"`
	UpdatedAt            string `json:"updatedAt"`
}

// toExternalIDPResponse never exposes the client secret — only whether
// one is stored.
func toExternalIDPResponse(e *core.ExternalIDP) externalIDPResponse {
	return externalIDPResponse{
		ID: e.ID.String(), Slug: e.Slug, DisplayName: e.DisplayName, Enabled: e.Enabled,
		Mode: string(e.Mode), IssuerURL: e.IssuerURL, AuthorizeURL: e.AuthorizeURL,
		TokenURL: e.TokenURL, UserinfoURL: e.UserinfoURL, JWKSURL: e.JWKSURL,
		ClientID: e.ClientID, HasClientSecret: len(e.ClientSecretEncrypted) > 0,
		Scopes: e.Scopes, SubjectField: e.SubjectField, EmailField: e.EmailField,
		EmailVerifiedField: e.EmailVerifiedField, NameField: e.NameField, ButtonIcon: e.ButtonIcon,
		TrustUnverifiedEmail: e.TrustUnverifiedEmail,
		CreatedAt:            e.CreatedAt.Format(time.RFC3339), UpdatedAt: e.UpdatedAt.Format(time.RFC3339),
	}
}

type externalIDPRequest struct {
	Slug         string `json:"slug"`
	DisplayName  string `json:"displayName"`
	Enabled      bool   `json:"enabled"`
	Mode         string `json:"mode"`
	IssuerURL    string `json:"issuerUrl"`
	AuthorizeURL string `json:"authorizeUrl"`
	TokenURL     string `json:"tokenUrl"`
	UserinfoURL  string `json:"userinfoUrl"`
	JWKSURL      string `json:"jwksUrl"`
	ClientID     string `json:"clientId"`
	// ClientSecret is plaintext in. On update, "" means "keep the stored
	// secret" — so the UI never has to round-trip the secret back.
	ClientSecret         string `json:"clientSecret"`
	Scopes               string `json:"scopes"`
	SubjectField         string `json:"subjectField"`
	EmailField           string `json:"emailField"`
	EmailVerifiedField   string `json:"emailVerifiedField"`
	NameField            string `json:"nameField"`
	ButtonIcon           string `json:"buttonIcon"`
	TrustUnverifiedEmail bool   `json:"trustUnverifiedEmail"`
}

func (r *externalIDPRequest) normalize() {
	r.Slug = strings.TrimSpace(r.Slug)
	r.DisplayName = strings.TrimSpace(r.DisplayName)
	r.Mode = strings.TrimSpace(r.Mode)
	r.IssuerURL = strings.TrimSpace(r.IssuerURL)
	r.AuthorizeURL = strings.TrimSpace(r.AuthorizeURL)
	r.TokenURL = strings.TrimSpace(r.TokenURL)
	r.UserinfoURL = strings.TrimSpace(r.UserinfoURL)
	r.JWKSURL = strings.TrimSpace(r.JWKSURL)
	r.ClientID = strings.TrimSpace(r.ClientID)
}

// validate checks the request shape. isCreate gates the client-secret
// requirement (update may omit it to keep the stored one). Returns an
// i18n error code + false on the first problem.
func (req *externalIDPRequest) validate(isCreate bool) (string, bool) {
	if !slugPattern.MatchString(req.Slug) {
		return "error.externalIdpInvalidSlug", false
	}
	if req.DisplayName == "" {
		return "error.externalIdpDisplayNameRequired", false
	}
	if req.Mode != oidc.ModeOIDC && req.Mode != oidc.ModeOAuth2 {
		return "error.externalIdpInvalidMode", false
	}
	if req.ClientID == "" {
		return "error.externalIdpClientIdRequired", false
	}
	if isCreate && req.ClientSecret == "" {
		return "error.externalIdpClientSecretRequired", false
	}
	if req.Mode == oidc.ModeOIDC {
		if req.IssuerURL == "" {
			return "error.externalIdpIssuerRequired", false
		}
		if oidc.RequireSecureURL(req.IssuerURL) != nil {
			return "error.externalIdpInsecureUrl", false
		}
	} else { // oauth2
		if req.AuthorizeURL == "" || req.TokenURL == "" || req.UserinfoURL == "" {
			return "error.externalIdpEndpointsRequired", false
		}
		for _, u := range []string{req.AuthorizeURL, req.TokenURL, req.UserinfoURL} {
			if oidc.RequireSecureURL(u) != nil {
				return "error.externalIdpInsecureUrl", false
			}
		}
	}
	return "", true
}

// applyTo writes the request's non-secret fields onto e. The caller sets
// ID, AppID, and ClientSecretEncrypted (which require encryption/identity
// the request body doesn't carry).
func (req *externalIDPRequest) applyTo(e *core.ExternalIDP) {
	e.Slug = req.Slug
	e.DisplayName = req.DisplayName
	e.Enabled = req.Enabled
	e.Mode = core.ExternalIDPMode(req.Mode)
	e.IssuerURL = req.IssuerURL
	e.AuthorizeURL = req.AuthorizeURL
	e.TokenURL = req.TokenURL
	e.UserinfoURL = req.UserinfoURL
	e.JWKSURL = req.JWKSURL
	e.ClientID = req.ClientID
	e.Scopes = strings.TrimSpace(req.Scopes)
	e.SubjectField = strings.TrimSpace(req.SubjectField)
	e.EmailField = strings.TrimSpace(req.EmailField)
	e.EmailVerifiedField = strings.TrimSpace(req.EmailVerifiedField)
	e.NameField = strings.TrimSpace(req.NameField)
	e.ButtonIcon = strings.TrimSpace(req.ButtonIcon)
	e.TrustUnverifiedEmail = req.TrustUnverifiedEmail
}

// adminAppForExternalIDP runs the admin auth + workspace + path-id +
// app-ownership checks shared by every handler here. Returns the
// workspace and the verified app id.
func (handler *RequestHandler) adminAppForExternalIDP(w http.ResponseWriter, r *http.Request) (*core.Workspace, uuid.UUID, bool) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return nil, uuid.Nil, false
	}
	productID, appID, ok := handler.resolvePathIDs(w, r)
	if !ok {
		return nil, uuid.Nil, false
	}
	if _, err := handler.repo.GetAppByIDForProduct(r.Context(), ws.ID, productID, appID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		} else {
			log.Err(err).Msg("external idp admin: load app failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		}
		return nil, uuid.Nil, false
	}
	return ws, appID, true
}

func (handler *RequestHandler) encryptExternalIDPSecret(id uuid.UUID, plaintext string) ([]byte, error) {
	return handler.encryptor.EncryptToBytesWithAAD(
		[]byte(plaintext),
		crypto.AAD("external_idps", "client_secret_encrypted", id),
	)
}

// HandleListExternalIDPs lists every configured provider for an app.
func (handler *RequestHandler) HandleListExternalIDPs(w http.ResponseWriter, r *http.Request) {
	_, appID, ok := handler.adminAppForExternalIDP(w, r)
	if !ok {
		return
	}
	list, err := handler.repo.ListExternalIDPsByApp(r.Context(), appID)
	if err != nil {
		log.Err(err).Msg("HandleListExternalIDPs: list failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	out := make([]externalIDPResponse, 0, len(list))
	for i := range list {
		out = append(out, toExternalIDPResponse(&list[i]))
	}
	utils.WriteJson(w, map[string]any{"externalIdps": out})
}

// HandleCreateExternalIDP provisions a new provider (encrypting the
// client secret) and returns it.
func (handler *RequestHandler) HandleCreateExternalIDP(w http.ResponseWriter, r *http.Request) {
	_, appID, ok := handler.adminAppForExternalIDP(w, r)
	if !ok {
		return
	}
	var req externalIDPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	req.normalize()
	if code, valid := req.validate(true); !valid {
		WriteError(w, r, code, http.StatusBadRequest)
		return
	}

	// Clean 409 on duplicate slug (the unique index is the real guard).
	if existing, err := handler.repo.GetExternalIDPByAppAndSlug(r.Context(), appID, req.Slug); err == nil && existing != nil {
		WriteError(w, r, "error.externalIdpSlugTaken", http.StatusConflict)
		return
	} else if err != nil && !errors.Is(err, repo.ErrExternalIDPNotFound) {
		log.Err(err).Msg("HandleCreateExternalIDP: slug pre-check failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// The AAD binds the ciphertext to the row id, so the id must exist
	// before encryption — generate it here rather than letting the repo.
	id, err := uuid.NewV4()
	if err != nil {
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	enc, err := handler.encryptExternalIDPSecret(id, req.ClientSecret)
	if err != nil {
		log.Err(err).Msg("HandleCreateExternalIDP: encrypt secret failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	e := &core.ExternalIDP{ID: id, AppID: appID, ClientSecretEncrypted: enc}
	req.applyTo(e)
	if err := handler.repo.CreateExternalIDP(r.Context(), e); err != nil {
		log.Err(err).Msg("HandleCreateExternalIDP: create failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJsonWithStatusCode(w, toExternalIDPResponse(e), http.StatusCreated)
}

// HandleUpdateExternalIDP replaces a provider's config. An empty
// clientSecret keeps the stored one (the UI never round-trips secrets).
func (handler *RequestHandler) HandleUpdateExternalIDP(w http.ResponseWriter, r *http.Request) {
	_, appID, ok := handler.adminAppForExternalIDP(w, r)
	if !ok {
		return
	}
	idpID, err := utils.GetPathUUID("idpId", r)
	if err != nil || idpID == uuid.Nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	existing, err := handler.repo.GetExternalIDPByID(r.Context(), appID, idpID)
	if err != nil {
		if errors.Is(err, repo.ErrExternalIDPNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
		} else {
			log.Err(err).Msg("HandleUpdateExternalIDP: load failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		}
		return
	}

	var req externalIDPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	req.normalize()
	if code, valid := req.validate(false); !valid {
		WriteError(w, r, code, http.StatusBadRequest)
		return
	}

	// Renaming to a slug another provider holds → 409.
	if req.Slug != existing.Slug {
		if other, gerr := handler.repo.GetExternalIDPByAppAndSlug(r.Context(), appID, req.Slug); gerr == nil && other != nil {
			WriteError(w, r, "error.externalIdpSlugTaken", http.StatusConflict)
			return
		}
	}

	// Secret merge: a provided secret is re-encrypted; an empty one keeps
	// the stored ciphertext (UpdateExternalIDP does a full overwrite, so
	// we must carry it forward or it'd be wiped).
	enc := existing.ClientSecretEncrypted
	if req.ClientSecret != "" {
		enc, err = handler.encryptExternalIDPSecret(idpID, req.ClientSecret)
		if err != nil {
			log.Err(err).Msg("HandleUpdateExternalIDP: encrypt secret failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
	}

	e := &core.ExternalIDP{ID: idpID, AppID: appID, ClientSecretEncrypted: enc, CreatedAt: existing.CreatedAt}
	req.applyTo(e)
	if err := handler.repo.UpdateExternalIDP(r.Context(), e); err != nil {
		if errors.Is(err, repo.ErrExternalIDPNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("HandleUpdateExternalIDP: update failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, toExternalIDPResponse(e))
}

// HandleDeleteExternalIDP removes a provider.
func (handler *RequestHandler) HandleDeleteExternalIDP(w http.ResponseWriter, r *http.Request) {
	_, appID, ok := handler.adminAppForExternalIDP(w, r)
	if !ok {
		return
	}
	idpID, err := utils.GetPathUUID("idpId", r)
	if err != nil || idpID == uuid.Nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	deleted, err := handler.repo.DeleteExternalIDP(r.Context(), appID, idpID)
	if err != nil {
		log.Err(err).Msg("HandleDeleteExternalIDP: delete failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !deleted {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleValidateExternalIDPDiscovery fetches an issuer's well-known doc
// and returns the resolved endpoints — the admin UI's "fetch discovery"
// button, so a misconfigured issuer fails before the provider is saved.
func (handler *RequestHandler) HandleValidateExternalIDPDiscovery(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := handler.adminAppForExternalIDP(w, r); !ok {
		return
	}
	var req struct {
		IssuerURL string `json:"issuerUrl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	req.IssuerURL = strings.TrimSpace(req.IssuerURL)
	if req.IssuerURL == "" || oidc.RequireSecureURL(req.IssuerURL) != nil {
		WriteError(w, r, "error.externalIdpInsecureUrl", http.StatusBadRequest)
		return
	}
	ep, err := oidc.Discover(r.Context(), req.IssuerURL)
	if err != nil {
		// Discovery failures are the admin's misconfiguration, not a
		// server fault — surface as a 400 with the reason.
		WriteErrorMsg(w, r, "Discovery failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	utils.WriteJson(w, map[string]any{
		"issuer":       ep.Issuer,
		"authorizeUrl": ep.Authorize,
		"tokenUrl":     ep.Token,
		"userinfoUrl":  ep.Userinfo,
		"jwksUrl":      ep.JWKS,
	})
}
