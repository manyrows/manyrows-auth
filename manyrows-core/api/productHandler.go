package api

import (
	"encoding/json"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"
	"net/http"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// adminAndProduct returns (account, workspace, project, ok)
// It ensures:
//  1. admin account is present in context
//  2. workspaceId is valid AND admin can access it
//  3. productId is valid AND belongs to that workspace
func (handler *RequestHandler) adminAndProduct(w http.ResponseWriter, r *http.Request) (*core.Account, *core.Workspace, *core.Product, bool) {
	acc, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return nil, nil, nil, false
	}
	productID, err := utils.GetPathUUID("productId", r)
	if productID == uuid.Nil || err != nil {
		WriteError(w, r, "error.missingProductId", http.StatusBadRequest)
		return nil, nil, nil, false
	}
	project, err := handler.repo.GetProduct(r.Context(), productID, ws.ID)
	if err != nil {
		log.Err(err).Msg("Could not get project")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return nil, nil, nil, false
	}
	if project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return nil, nil, nil, false
	}
	if project.WorkspaceID != ws.ID {
		WriteError(w, r, "error.projectNotInWorkspace", http.StatusNotFound)
		return nil, nil, nil, false
	}
	return acc, ws, project, true
}

func (handler *RequestHandler) adminAndWorkspace(w http.ResponseWriter, r *http.Request) (*core.Account, *core.Workspace, bool) {
	acc, ok := core.AdminAccountFromContext(r.Context())
	if !ok || acc == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return nil, nil, false
	}

	workspaceID, err := utils.GetPathUUID("workspaceId", r)
	if workspaceID == uuid.Nil || err != nil {
		WriteError(w, r, "error.missingWorkspaceId", http.StatusBadRequest)
		return nil, nil, false
	}

	ws, ok, err := handler.GetWorkspaceAsAdmin(r.Context(), workspaceID, acc)
	if err != nil {
		log.Err(err).Msg("Could not get workspace")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return nil, nil, false
	}
	if !ok {
		WriteError(w, r, "error.workspaceNotFound", http.StatusForbidden)
		return nil, nil, false
	}

	return acc, ws, true
}

func (handler *RequestHandler) GetProducts(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	products, err := handler.repo.GetProductsByWorkspaceID(r.Context(), ws.ID)
	if err != nil {
		log.Err(err).Msg("Could not get products")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, products)
}

func (handler *RequestHandler) GetProduct(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	productID, err := utils.GetPathUUID("productId", r)
	if productID == uuid.Nil || err != nil {
		WriteError(w, r, "error.missingProductId", http.StatusBadRequest)
		return
	}

	project, err := handler.repo.GetProduct(r.Context(), productID, ws.ID)
	if err != nil {
		log.Err(err).Msg("Could not get project")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return
	}

	utils.WriteJson(w, project)
}

// maxProductsPerWorkspace is a hard server-side cap. Plan-based
// limits were removed; this guards against runaway creation.
const maxProductsPerWorkspace = 100

func (handler *RequestHandler) CreateProduct(w http.ResponseWriter, r *http.Request) {
	acc, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	count, err := handler.repo.CountProductsByWorkspaceID(r.Context(), ws.ID)
	if err != nil {
		log.Err(err).Msg("CreateProduct: count failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if count >= maxProductsPerWorkspace {
		WriteErrorf(w, r, "error.limitReached", http.StatusConflict, "Products", maxProductsPerWorkspace)
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		WriteError(w, r, "error.nameRequired", http.StatusBadRequest)
		return
	}

	// IMPORTANT: your repo InsertProduct takes a VALUE, so if it generates an ID internally,
	// the handler will never see it. Generate it here so we always have it for the response.
	newID := utils.NewUUID()

	p := core.Product{
		ID:          newID,
		WorkspaceID: ws.ID,
		Name:        req.Name,
		CreatedBy:   acc.ID,
	}

	if err := handler.repo.InsertProduct(r.Context(), p); err != nil {
		log.Err(err).Msg("Could not insert project")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Seed a default "User" role. Best-effort: role creation failure should not
	// block project creation. The role is a regular record — customers can rename,
	// edit, or delete it like any other.
	if _, err := handler.repo.CreateRole(r.Context(), repo.CreateRoleParams{
		ProductID: p.ID,
		Name:      "User",
		Slug:      "user",
		Now:       time.Now().UTC(),
	}); err != nil {
		log.Warn().Err(err).Str("productId", p.ID.String()).Msg("failed to seed default 'User' role; continuing")
	}

	// Best-effort: load the DB version (created_at/updated_at, etc.) for the response.
	after := p
	if got, err := handler.repo.GetProduct(r.Context(), newID, ws.ID); err == nil && got != nil {
		after = *got
	}

	utils.WriteJsonWithStatusCode(w, after, http.StatusCreated)
}

func (handler *RequestHandler) UpdateProduct(w http.ResponseWriter, r *http.Request) {
	acc, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	productID, err := utils.GetPathUUID("productId", r)
	if productID == uuid.Nil || err != nil {
		WriteError(w, r, "error.missingProductId", http.StatusBadRequest)
		return
	}

	project, err := handler.repo.GetProduct(r.Context(), productID, ws.ID)
	if err != nil {
		log.Err(err).Msg("Could not get project")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return
	}

	_ = *project

	var req struct {
		Name *string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	var changed []string

	if req.Name != nil {
		v := strings.TrimSpace(*req.Name)
		if v == "" {
			WriteError(w, r, "error.nameEmpty", http.StatusBadRequest)
			return
		}
		project.Name = v
		changed = append(changed, "name")
	}
	_ = acc

	if err := handler.repo.UpdateProduct(r.Context(), project); err != nil {
		log.Err(err).Msg("Could not update project")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// DeleteProduct deletes a project in a workspace.
// Assumes route like: DELETE /admin/workspace/{workspaceId}/products/{productId}
func (handler *RequestHandler) DeleteProduct(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	productID, err := utils.GetPathUUID("productId", r)
	if productID == uuid.Nil || err != nil {
		WriteError(w, r, "error.missingProductId", http.StatusBadRequest)
		return
	}

	// Ensure it exists + belongs to this workspace
	project, err := handler.repo.GetProduct(r.Context(), productID, ws.ID)
	if err != nil {
		log.Err(err).Msg("Could not get project")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return
	}

	_ = *project

	if err := handler.repo.DeleteProduct(r.Context(), project.ID, ws.ID); err != nil {
		log.Err(err).Msg("Could not delete project")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
