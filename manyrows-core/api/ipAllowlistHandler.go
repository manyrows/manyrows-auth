package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

const maxIPAllowlistPerApp = 50

func (handler *RequestHandler) HandleGetIPAllowlist(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	appID, err := utils.GetPathUUID("appId", r)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	app, err := handler.repo.GetAppByID(r.Context(), appID)
	if err != nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	if app.WorkspaceID != ws.ID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	entries, err := handler.repo.GetIPAllowlist(r.Context(), app.ID)
	if err != nil {
		log.Err(err).Msg("failed to get IP allowlist")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, entries, http.StatusOK)
}

func (handler *RequestHandler) HandleDeleteIPAllowlistEntry(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	if !handler.requireOwner(w, r) {
		return
	}

	appID, err := utils.GetPathUUID("appId", r)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	app, err := handler.repo.GetAppByID(r.Context(), appID)
	if err != nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	if app.WorkspaceID != ws.ID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	id, err := utils.GetPathUUID("id", r)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	if err := handler.repo.DeleteIPAllowlistEntry(r.Context(), app.ID, id); err != nil {
		log.Err(err).Msg("failed to delete IP allowlist entry")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type CreateIPAllowlistEntryRequest struct {
	IPRange     string `json:"ipRange"`
	Description string `json:"description"`
}

func (handler *RequestHandler) HandleCreateIPAllowlistEntry(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	if !handler.requireOwner(w, r) {
		return
	}

	appID, err := utils.GetPathUUID("appId", r)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	app, err := handler.repo.GetAppByID(r.Context(), appID)
	if err != nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	if app.WorkspaceID != ws.ID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	var req CreateIPAllowlistEntryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode IP allowlist entry request")
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	ipRange := strings.TrimSpace(req.IPRange)
	if ipRange == "" {
		WriteError(w, r, "error.ipRangeRequired", http.StatusBadRequest)
		return
	}

	// Validate IP or CIDR
	if !isValidIPOrCIDR(ipRange) {
		WriteError(w, r, "error.invalidIpRange", http.StatusBadRequest)
		return
	}

	description := strings.TrimSpace(req.Description)

	entry := core.IPAllowlistEntry{
		ID:          utils.NewUUID(),
		AppID:       app.ID,
		IPRange:     ipRange,
		Description: description,
		CreatedAt:   time.Now().UTC(),
	}

	inserted, err := handler.repo.InsertIPAllowlistEntryWithLimit(r.Context(), entry, maxIPAllowlistPerApp)
	if err != nil {
		// Check for duplicate
		if repo.IsUniqueViolation(err) {
			WriteError(w, r, "error.ipRangeExists", http.StatusConflict)
			return
		}
		log.Err(err).Msg("failed to insert IP allowlist entry")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !inserted {
		WriteErrorf(w, r, "error.limitReached", http.StatusConflict, "IP allowlist entries", maxIPAllowlistPerApp)
		return
	}

	utils.WriteJsonWithStatusCode(w, entry, http.StatusCreated)
}

type UpdateIPAllowlistEntryRequest struct {
	IPRange     *string `json:"ipRange"`
	Description *string `json:"description"`
}

func (handler *RequestHandler) HandleUpdateIPAllowlistEntry(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	if !handler.requireOwner(w, r) {
		return
	}

	appID, err := utils.GetPathUUID("appId", r)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	app, err := handler.repo.GetAppByID(r.Context(), appID)
	if err != nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	if app.WorkspaceID != ws.ID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	id, err := utils.GetPathUUID("id", r)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	var req UpdateIPAllowlistEntryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode IP allowlist update request")
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Get existing entry to merge fields
	entries, err := handler.repo.GetIPAllowlist(r.Context(), app.ID)
	if err != nil {
		log.Err(err).Msg("failed to get IP allowlist")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	var existing *core.IPAllowlistEntry
	for i := range entries {
		if entries[i].ID == id {
			existing = &entries[i]
			break
		}
	}
	if existing == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	ipRange := existing.IPRange
	if req.IPRange != nil {
		ipRange = strings.TrimSpace(*req.IPRange)
	}
	description := existing.Description
	if req.Description != nil {
		description = strings.TrimSpace(*req.Description)
	}

	if ipRange == "" {
		WriteError(w, r, "error.ipRangeRequired", http.StatusBadRequest)
		return
	}

	if !isValidIPOrCIDR(ipRange) {
		WriteError(w, r, "error.invalidIpRange", http.StatusBadRequest)
		return
	}

	updated, err := handler.repo.UpdateIPAllowlistEntry(r.Context(), app.ID, id, ipRange, description)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		if repo.IsUniqueViolation(err) {
			WriteError(w, r, "error.ipRangeExists", http.StatusConflict)
			return
		}
		log.Err(err).Msg("failed to update IP allowlist entry")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, updated, http.StatusOK)
}

// isValidIPOrCIDR checks if the string is a valid IP address or CIDR range.
func isValidIPOrCIDR(s string) bool {
	// Try parsing as CIDR first
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}

	// Try parsing as plain IP
	ip := net.ParseIP(s)
	return ip != nil
}
