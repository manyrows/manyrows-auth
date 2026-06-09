package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// S2S webhook self-service: a customer backend manages, by API key, the
// endpoints ManyRows POSTs auth events to. Mirrors the admin webhook handlers
// (api/webhookHandler.go), reusing the same request types, validators
// (ValidateWebhookURL / validateWebhookEvents), secret generator, and repo
// methods — only the auth/scoping (server context + serverActorID) differs.

func (handler *RequestHandler) serverWebhookApp(w http.ResponseWriter, r *http.Request) (*core.App, bool) {
	app, ok := core.AppFromContext(r.Context())
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return nil, false
	}
	return app, true
}

type ServerWebhooksResponse struct {
	Webhooks []core.Webhook `json:"webhooks"`
}

// ServerListWebhooks lists the app's webhook subscriptions (secrets redacted).
// GET /x/{workspaceSlug}/api/v1/apps/{appId}/webhooks
func (handler *RequestHandler) ServerListWebhooks(w http.ResponseWriter, r *http.Request) {
	app, ok := handler.serverWebhookApp(w, r)
	if !ok {
		return
	}
	webhooks, err := handler.repo.GetWebhooksByAppID(r.Context(), app.ID)
	if err != nil {
		log.Err(err).Msg("ServerListWebhooks: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	out := make([]core.Webhook, 0, len(webhooks))
	for _, wh := range webhooks {
		wh.Secret = "" // never expose the signing secret after creation
		out = append(out, wh)
	}
	utils.WriteJson(w, ServerWebhooksResponse{Webhooks: out})
}

// ServerCreateWebhook registers a webhook subscription. The signing secret is
// returned ONCE in this response (redacted everywhere after).
// POST /x/{workspaceSlug}/api/v1/apps/{appId}/webhooks
func (handler *RequestHandler) ServerCreateWebhook(w http.ResponseWriter, r *http.Request) {
	project, ok := core.ProjectFromContext(r.Context())
	if !ok || project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return
	}
	app, ok := handler.serverWebhookApp(w, r)
	if !ok {
		return
	}

	var req createWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" || !ValidateWebhookURL(req.URL, handler.config.IsDevMode()) {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if !validateWebhookEvents(req.Events) {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	secret, err := generateWebhookSecret()
	if err != nil {
		log.Err(err).Msg("ServerCreateWebhook: secret generation failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC()
	wh := core.Webhook{
		ID:          utils.NewUUID(),
		ProjectID:   project.ID,
		AppID:       app.ID,
		URL:         req.URL,
		Events:      req.Events,
		Status:      "active",
		Description: strings.TrimSpace(req.Description),
		CreatedAt:   now,
		UpdatedAt:   now,
		CreatedBy:   serverActorID(r.Context()),
	}
	// Store the secret only as AAD-bound ciphertext; surface the plaintext once below.
	wh.SecretEncrypted, err = handler.encryptWebhookSecret(secret, wh.ID)
	if err != nil {
		log.Err(err).Msg("ServerCreateWebhook: secret encryption failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	inserted, err := handler.repo.InsertWebhookWithLimit(r.Context(), wh, maxWebhooksPerApp)
	if err != nil {
		log.Err(err).Msg("ServerCreateWebhook: insert failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !inserted {
		WriteErrorf(w, r, "error.limitReached", http.StatusConflict, "webhooks", maxWebhooksPerApp)
		return
	}

	wh.Secret = secret // returned once; SecretEncrypted is json:"-"
	utils.WriteJsonWithStatusCode(w, wh, http.StatusCreated)
}

// ServerGetWebhook fetches one webhook subscription (secret redacted).
// GET /x/{workspaceSlug}/api/v1/apps/{appId}/webhooks/{webhookId}
func (handler *RequestHandler) ServerGetWebhook(w http.ResponseWriter, r *http.Request) {
	app, ok := handler.serverWebhookApp(w, r)
	if !ok {
		return
	}
	id, err := uuid.FromString(chi.URLParam(r, "webhookId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	wh, found, err := handler.repo.GetWebhookByID(r.Context(), id, app.ID)
	if err != nil {
		log.Err(err).Msg("ServerGetWebhook: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !found {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	wh.Secret = ""
	utils.WriteJson(w, wh)
}

// ServerUpdateWebhook patches a webhook subscription (URL, events, status,
// description). The secret can't be changed here.
// PATCH /x/{workspaceSlug}/api/v1/apps/{appId}/webhooks/{webhookId}
func (handler *RequestHandler) ServerUpdateWebhook(w http.ResponseWriter, r *http.Request) {
	app, ok := handler.serverWebhookApp(w, r)
	if !ok {
		return
	}
	id, err := uuid.FromString(chi.URLParam(r, "webhookId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	wh, found, err := handler.repo.GetWebhookByID(r.Context(), id, app.ID)
	if err != nil {
		log.Err(err).Msg("ServerUpdateWebhook: lookup failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !found {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	var req updateWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if req.URL != nil {
		u := strings.TrimSpace(*req.URL)
		if u == "" || !ValidateWebhookURL(u, handler.config.IsDevMode()) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		wh.URL = u
	}
	if req.Events != nil {
		if !validateWebhookEvents(req.Events) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		wh.Events = req.Events
	}
	if req.Status != nil {
		s := strings.TrimSpace(*req.Status)
		if s != "active" && s != "disabled" {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		wh.Status = s
	}
	if req.Description != nil {
		wh.Description = strings.TrimSpace(*req.Description)
	}
	wh.UpdatedAt = time.Now().UTC()

	if err := handler.repo.UpdateWebhook(r.Context(), wh); err != nil {
		log.Err(err).Msg("ServerUpdateWebhook: update failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	wh.Secret = ""
	utils.WriteJson(w, wh)
}

// ServerRotateWebhookSecret issues a fresh signing secret for a webhook and
// returns it ONCE (redacted everywhere else). Use after a suspected leak.
// POST /x/{workspaceSlug}/api/v1/apps/{appId}/webhooks/{webhookId}/rotate-secret
func (handler *RequestHandler) ServerRotateWebhookSecret(w http.ResponseWriter, r *http.Request) {
	app, ok := handler.serverWebhookApp(w, r)
	if !ok {
		return
	}
	id, err := uuid.FromString(chi.URLParam(r, "webhookId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	wh, found, err := handler.repo.GetWebhookByID(r.Context(), id, app.ID)
	if err != nil {
		log.Err(err).Msg("ServerRotateWebhookSecret: lookup failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !found {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	secret, err := generateWebhookSecret()
	if err != nil {
		log.Err(err).Msg("ServerRotateWebhookSecret: secret generation failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	secretEnc, err := handler.encryptWebhookSecret(secret, id)
	if err != nil {
		log.Err(err).Msg("ServerRotateWebhookSecret: secret encryption failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if err := handler.repo.RotateWebhookSecret(r.Context(), id, app.ID, secretEnc); err != nil {
		log.Err(err).Msg("ServerRotateWebhookSecret: rotate failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	wh.Secret = secret // returned once; SecretEncrypted is json:"-"
	wh.UpdatedAt = time.Now().UTC()
	utils.WriteJson(w, wh)
}

// ServerDeleteWebhook removes a webhook subscription.
// DELETE /x/{workspaceSlug}/api/v1/apps/{appId}/webhooks/{webhookId}
func (handler *RequestHandler) ServerDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	app, ok := handler.serverWebhookApp(w, r)
	if !ok {
		return
	}
	id, err := uuid.FromString(chi.URLParam(r, "webhookId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	_, found, err := handler.repo.GetWebhookByID(r.Context(), id, app.ID)
	if err != nil {
		log.Err(err).Msg("ServerDeleteWebhook: lookup failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !found {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	if err := handler.repo.DeleteWebhook(r.Context(), id, app.ID); err != nil {
		log.Err(err).Msg("ServerDeleteWebhook: delete failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
