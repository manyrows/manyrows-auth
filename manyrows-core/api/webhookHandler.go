package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

const maxWebhooksPerApp = 10

// generateWebhookSecret returns a random 256-bit hex secret used to sign
// webhook deliveries (HMAC). Shared by the admin and S2S create paths.
func generateWebhookSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// validWebhookEvents is the allowlist of event names that can be subscribed to.
// Currently limited to auth-related events only.
var validWebhookEvents = map[string]struct{}{
	"user.login":            {},
	"user.register":         {},
	"user.logout":           {},
	"user.password_change":  {},
	"user.password_reset":   {},
	"user.delete":           {},
	"user.created":          {},
	"user.email_change":     {},
	"user.passkey_register": {},
	"user.passkey_delete":   {},
}

// validateWebhookEvents checks that all event names are in the allowlist and at least one is provided.
func validateWebhookEvents(events []string) bool {
	if len(events) == 0 {
		return false
	}
	for _, e := range events {
		if _, ok := validWebhookEvents[e]; !ok {
			return false
		}
	}
	return true
}

// ValidateWebhookURL checks that the URL is HTTPS and does not point to private/loopback addresses.
// In dev mode, HTTP and localhost are allowed.
func ValidateWebhookURL(rawURL string, devMode bool) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	if devMode {
		return u.Scheme == "https" || u.Scheme == "http"
	}

	if u.Scheme != "https" {
		return false
	}

	host := u.Hostname()

	// Block localhost by name
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return false
	}

	// Resolve and check for private IPs
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return false
		}
	}
	return true
}

// adminProjectAndApp resolves workspace, project, and app from URL params.
// It verifies the app belongs to the workspace.
func (handler *RequestHandler) adminProjectAndApp(w http.ResponseWriter, r *http.Request) (*core.Account, *core.Workspace, *core.Project, *core.App, bool) {
	acc, ws, project, ok := handler.adminAndProject(w, r)
	if !ok {
		return nil, nil, nil, nil, false
	}

	appID, err := utils.GetPathUUID("appId", r)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return nil, nil, nil, nil, false
	}

	app, err := handler.repo.GetAppByID(r.Context(), appID)
	if err != nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return nil, nil, nil, nil, false
	}
	if app.WorkspaceID != ws.ID || app.ProjectID != project.ID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return nil, nil, nil, nil, false
	}

	return acc, ws, project, &app, true
}

// HandleListWebhooks — GET /projects/{projectId}/apps/{appId}/webhooks
func (handler *RequestHandler) HandleListWebhooks(w http.ResponseWriter, r *http.Request) {
	_, _, _, app, ok := handler.adminProjectAndApp(w, r)
	if !ok {
		return
	}

	webhooks, err := handler.repo.GetWebhooksByAppID(r.Context(), app.ID)
	if err != nil {
		log.Err(err).Msg("failed to get webhooks")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Clear secrets from response
	for i := range webhooks {
		webhooks[i].Secret = ""
	}

	utils.WriteJsonWithStatusCode(w, webhooks, http.StatusOK)
}

// HandleGetAppWebhookHealth — GET /projects/{projectId}/apps/{appId}/webhooks/health
//
// Stat cards (totals, 24h delivery counts, pending retries) plus the most
// recent failures for the per-app Webhooks dashboard.
func (handler *RequestHandler) HandleGetAppWebhookHealth(w http.ResponseWriter, r *http.Request) {
	_, _, _, app, ok := handler.adminProjectAndApp(w, r)
	if !ok {
		return
	}

	health, err := handler.repo.GetAppWebhookHealth(r.Context(), app.ID, 25)
	if err != nil {
		log.Err(err).Msg("failed to get webhook health")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, health, http.StatusOK)
}

type createWebhookRequest struct {
	URL         string   `json:"url"`
	Events      []string `json:"events"`
	Description string   `json:"description"`
}

// HandleCreateWebhook — POST /projects/{projectId}/apps/{appId}/webhooks
func (handler *RequestHandler) HandleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	acc, _, project, app, ok := handler.adminProjectAndApp(w, r)
	if !ok {
		return
	}

	var req createWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if !ValidateWebhookURL(req.URL, handler.config.IsDevMode()) {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	if !validateWebhookEvents(req.Events) {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	secret, err := generateWebhookSecret()
	if err != nil {
		log.Err(err).Msg("failed to generate webhook secret")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC()
	wh := core.Webhook{
		ID:          utils.NewUUID(),
		ProjectID:   project.ID,
		AppID:       app.ID,
		URL:         req.URL,
		Secret:      secret,
		Events:      req.Events,
		Status:      "active",
		Description: strings.TrimSpace(req.Description),
		CreatedAt:   now,
		UpdatedAt:   now,
		CreatedBy:   acc.ID,
	}

	// Atomic insert with limit check to avoid TOCTOU race
	inserted, err := handler.repo.InsertWebhookWithLimit(r.Context(), wh, maxWebhooksPerApp)
	if err != nil {
		log.Err(err).Msg("failed to insert webhook")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !inserted {
		WriteErrorf(w, r, "error.limitReached", http.StatusConflict, "webhooks", maxWebhooksPerApp)
		return
	}

	// Return with secret visible (only on create)
	utils.WriteJsonWithStatusCode(w, wh, http.StatusCreated)
}

// HandleGetWebhook — GET /projects/{projectId}/apps/{appId}/webhooks/{webhookId}
func (handler *RequestHandler) HandleGetWebhook(w http.ResponseWriter, r *http.Request) {
	_, _, _, app, ok := handler.adminProjectAndApp(w, r)
	if !ok {
		return
	}

	webhookID, err := uuid.FromString(chi.URLParam(r, "webhookId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	wh, found, err := handler.repo.GetWebhookByID(r.Context(), webhookID, app.ID)
	if err != nil {
		log.Err(err).Msg("failed to get webhook")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !found {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	// Clear secret
	wh.Secret = ""

	utils.WriteJsonWithStatusCode(w, wh, http.StatusOK)
}

type updateWebhookRequest struct {
	URL         *string  `json:"url"`
	Events      []string `json:"events"`
	Status      *string  `json:"status"`
	Description *string  `json:"description"`
}

// HandleUpdateWebhook — PATCH /projects/{projectId}/apps/{appId}/webhooks/{webhookId}
func (handler *RequestHandler) HandleUpdateWebhook(w http.ResponseWriter, r *http.Request) {
	_, _, _, app, ok := handler.adminProjectAndApp(w, r)
	if !ok {
		return
	}

	webhookID, err := uuid.FromString(chi.URLParam(r, "webhookId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	wh, found, err := handler.repo.GetWebhookByID(r.Context(), webhookID, app.ID)
	if err != nil {
		log.Err(err).Msg("failed to get webhook for update")
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
		if u == "" {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		if !ValidateWebhookURL(u, handler.config.IsDevMode()) {
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
		log.Err(err).Msg("failed to update webhook")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Clear secret
	wh.Secret = ""

	utils.WriteJsonWithStatusCode(w, wh, http.StatusOK)
}

// HandleDeleteWebhook — DELETE /projects/{projectId}/apps/{appId}/webhooks/{webhookId}
func (handler *RequestHandler) HandleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	_, _, _, app, ok := handler.adminProjectAndApp(w, r)
	if !ok {
		return
	}

	webhookID, err := uuid.FromString(chi.URLParam(r, "webhookId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	_, found, err := handler.repo.GetWebhookByID(r.Context(), webhookID, app.ID)
	if err != nil {
		log.Err(err).Msg("failed to get webhook for deletion")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !found {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	if err := handler.repo.DeleteWebhook(r.Context(), webhookID, app.ID); err != nil {
		log.Err(err).Msg("failed to delete webhook")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// HandleListWebhookDeliveries — GET /projects/{projectId}/apps/{appId}/webhooks/{webhookId}/deliveries
func (handler *RequestHandler) HandleListWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	_, _, _, app, ok := handler.adminProjectAndApp(w, r)
	if !ok {
		return
	}

	webhookID, err := uuid.FromString(chi.URLParam(r, "webhookId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Verify webhook belongs to app
	_, found, err := handler.repo.GetWebhookByID(r.Context(), webhookID, app.ID)
	if err != nil {
		log.Err(err).Msg("failed to get webhook for deliveries")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !found {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	limit := 20
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if limit > 100 {
		limit = 100
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	deliveries, err := handler.repo.GetDeliveriesByWebhookID(r.Context(), webhookID, limit, offset)
	if err != nil {
		log.Err(err).Msg("failed to get webhook deliveries")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, deliveries, http.StatusOK)
}

// HandleRetryWebhookDelivery — POST /projects/{projectId}/apps/{appId}/webhooks/{webhookId}/deliveries/{deliveryId}/retry
func (handler *RequestHandler) HandleRetryWebhookDelivery(w http.ResponseWriter, r *http.Request) {
	_, _, _, app, ok := handler.adminProjectAndApp(w, r)
	if !ok {
		return
	}

	webhookID, err := uuid.FromString(chi.URLParam(r, "webhookId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	deliveryIDStr := chi.URLParam(r, "deliveryId")
	deliveryID, err := uuid.FromString(deliveryIDStr)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Verify webhook belongs to app
	_, found, err := handler.repo.GetWebhookByID(r.Context(), webhookID, app.ID)
	if err != nil {
		log.Err(err).Msg("failed to get webhook for retry")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !found {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	// Get the delivery by ID directly
	d, found2, err := handler.repo.GetDeliveryByID(r.Context(), webhookID, deliveryID)
	if err != nil {
		log.Err(err).Msg("failed to get delivery for retry")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !found2 {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	delivery := &d

	// Reset delivery for retry
	now := time.Now().UTC()
	delivery.Status = "pending"
	delivery.Attempts = 0
	delivery.NextRetryAt = &now
	delivery.CompletedAt = nil

	if err := handler.repo.UpdateWebhookDelivery(r.Context(), *delivery); err != nil {
		log.Err(err).Msg("failed to update delivery for retry")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, delivery, http.StatusOK)
}
