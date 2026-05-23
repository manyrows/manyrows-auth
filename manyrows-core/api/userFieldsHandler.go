package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

var userFieldKeyRegex = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

const maxUserFieldsPerPool = 50

// --------------------
// Request / Responses
// --------------------

type UserFieldsResponse struct {
	UserFields []core.UserField `json:"userFields"`
}

type UserFieldResponse struct {
	UserField core.UserField `json:"userField"`
}

type UserFieldValuesResponse struct {
	Values []core.UserFieldValue `json:"values"`
}

type UserFieldValueResponse struct {
	Value core.UserFieldValue `json:"value"`
}

type CreateUserFieldRequest struct {
	Key          string `json:"key"`
	Label        string `json:"label"`      // required — label shown to the user
	ValueType    string `json:"valueType"`  // string|bool|date
	Visibility   string `json:"visibility"` // client|server
	UserEditable *bool  `json:"userEditable"`
	Status       string `json:"status"`
}

type UpdateUserFieldRequest struct {
	Label        *string `json:"label"`
	Visibility   *string `json:"visibility"`
	ValueType    *string `json:"valueType"`
	UserEditable *bool   `json:"userEditable"`
	Status       *string `json:"status"`
}

type UpsertUserFieldValueRequest struct {
	Value json.RawMessage `json:"value"`
}

// --------------------
// Pool resolver
// --------------------

// adminAndPool validates the admin + workspace, then loads the user
// pool from {poolId} in the URL, returning it only if it belongs to
// the workspace. Single helper so every user-field handler shares
// the same scope check.
func (handler *RequestHandler) adminAndPool(w http.ResponseWriter, r *http.Request) (*core.Account, *core.Workspace, *core.UserPool, bool) {
	acc, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return nil, nil, nil, false
	}
	poolID, err := uuid.FromString(chi.URLParam(r, "poolId"))
	if err != nil || poolID == uuid.Nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return nil, nil, nil, false
	}
	pool, err := handler.repo.GetUserPoolByID(r.Context(), poolID)
	if err != nil || pool == nil || pool.WorkspaceID != ws.ID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return nil, nil, nil, false
	}
	return acc, ws, pool, true
}

// --------------------
// Handlers
// --------------------

func (handler *RequestHandler) HandleGetUserFields(w http.ResponseWriter, r *http.Request) {
	_, _, pool, ok := handler.adminAndPool(w, r)
	if !ok {
		return
	}

	fields, err := handler.repo.GetUserFieldsByUserPoolID(r.Context(), pool.ID)
	if err != nil {
		log.Err(err).Msg("HandleGetUserFields: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, UserFieldsResponse{UserFields: fields}, http.StatusOK)
}

func (handler *RequestHandler) HandleCreateUserField(w http.ResponseWriter, r *http.Request) {
	acc, _, pool, ok := handler.adminAndPool(w, r)
	if !ok {
		return
	}

	var req CreateUserFieldRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	// Check limit
	count, err := handler.repo.CountUserFieldsByUserPoolID(r.Context(), pool.ID)
	if err != nil {
		log.Err(err).Msg("HandleCreateUserField: count failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if count >= maxUserFieldsPerPool {
		WriteErrorf(w, r, "error.limitReached", http.StatusConflict, "User Fields", maxUserFieldsPerPool)
		return
	}

	key := strings.TrimSpace(req.Key)
	if key == "" || !userFieldKeyRegex.MatchString(key) {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	label := strings.TrimSpace(req.Label)
	if label == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	vt := strings.TrimSpace(strings.ToLower(req.ValueType))
	if vt == "" {
		vt = "string"
	}
	if !core.UserFieldValueType(vt).IsValid() {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	vis := strings.TrimSpace(strings.ToLower(req.Visibility))
	if vis == "" {
		vis = core.UserFieldVisibilityServer
	}
	if vis != core.UserFieldVisibilityClient && vis != core.UserFieldVisibilityServer {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	status := strings.TrimSpace(strings.ToLower(req.Status))
	if status == "" {
		status = "active"
	}
	if status != "active" && status != "archived" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	userEditable := false
	if req.UserEditable != nil {
		userEditable = *req.UserEditable
	}
	// Server-only fields cannot be user-editable
	if vis == core.UserFieldVisibilityServer {
		userEditable = false
	}

	now := time.Now().UTC()

	uf := core.UserField{
		ID:           utils.NewUUID(),
		UserPoolID:   pool.ID,
		Key:          key,
		ValueType:    core.UserFieldValueType(vt),
		Visibility:   vis,
		UserEditable: userEditable,
		Label:        label,
		Status:       status,
		CreatedAt:    now,
		UpdatedAt:    now,
		CreatedBy:    acc.ID,
	}

	created, err := handler.repo.CreateUserField(r.Context(), uf)
	if err != nil {
		if errors.Is(err, repo.ErrConflict) {
			WriteError(w, r, "error.conflict", http.StatusConflict)
			return
		}
		log.Err(err).Msg("HandleCreateUserField: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, UserFieldResponse{UserField: created}, http.StatusCreated)
}

func (handler *RequestHandler) HandleGetUserField(w http.ResponseWriter, r *http.Request) {
	_, _, pool, ok := handler.adminAndPool(w, r)
	if !ok {
		return
	}

	fieldID, err := uuid.FromString(chi.URLParam(r, "userFieldId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	uf, err := handler.repo.GetUserFieldByID(r.Context(), pool.ID, fieldID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("HandleGetUserField: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, UserFieldResponse{UserField: uf}, http.StatusOK)
}

func (handler *RequestHandler) HandleUpdateUserField(w http.ResponseWriter, r *http.Request) {
	_, _, pool, ok := handler.adminAndPool(w, r)
	if !ok {
		return
	}

	fieldID, err := uuid.FromString(chi.URLParam(r, "userFieldId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	before, err := handler.repo.GetUserFieldByID(r.Context(), pool.ID, fieldID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("HandleUpdateUserField: failed to get field")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	var req UpdateUserFieldRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	// Normalize
	var lbl *string
	if req.Label != nil {
		l := strings.TrimSpace(*req.Label)
		if l == "" {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		lbl = &l
	}

	var vis *string
	if req.Visibility != nil {
		v := strings.TrimSpace(strings.ToLower(*req.Visibility))
		if v != core.UserFieldVisibilityClient && v != core.UserFieldVisibilityServer {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		vis = &v
	}

	var vt *string
	if req.ValueType != nil {
		v := strings.TrimSpace(strings.ToLower(*req.ValueType))
		if !core.UserFieldValueType(v).IsValid() {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		vt = &v
	}

	var status *string
	if req.Status != nil {
		s := strings.TrimSpace(strings.ToLower(*req.Status))
		if s != "active" && s != "archived" {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		status = &s
	}

	// Server-only fields cannot be user-editable
	effectiveVis := before.Visibility
	if vis != nil {
		effectiveVis = *vis
	}
	if effectiveVis == core.UserFieldVisibilityServer {
		f := false
		req.UserEditable = &f
	}

	updated, err := handler.repo.UpdateUserField(r.Context(), pool.ID, fieldID, lbl, vis, vt, req.UserEditable, status)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		if errors.Is(err, repo.ErrConflict) {
			WriteError(w, r, "error.conflict", http.StatusConflict)
			return
		}
		log.Err(err).Msg("HandleUpdateUserField: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, UserFieldResponse{UserField: updated}, http.StatusOK)
}

func (handler *RequestHandler) HandleDeleteUserField(w http.ResponseWriter, r *http.Request) {
	_, _, pool, ok := handler.adminAndPool(w, r)
	if !ok {
		return
	}

	fieldID, err := uuid.FromString(chi.URLParam(r, "userFieldId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	if err := handler.repo.DeleteUserField(r.Context(), pool.ID, fieldID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("HandleDeleteUserField: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --------------------
// Values
// --------------------

func (handler *RequestHandler) HandleGetUserFieldValues(w http.ResponseWriter, r *http.Request) {
	_, _, pool, ok := handler.adminAndPool(w, r)
	if !ok {
		return
	}

	userIDStr := r.URL.Query().Get("userId")
	if userIDStr == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	userID, err := uuid.FromString(userIDStr)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Confirm the user lives in this pool. Otherwise a stray user_id
	// would let any admin in the workspace read another pool's
	// values via the wrong URL.
	user, err := handler.repo.GetUserByID(r.Context(), userID)
	if err != nil || user == nil || user.UserPoolID != pool.ID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	values, err := handler.repo.GetUserFieldValuesByUser(r.Context(), userID)
	if err != nil {
		log.Err(err).Msg("HandleGetUserFieldValues: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, UserFieldValuesResponse{Values: values}, http.StatusOK)
}

// upsertUserFieldValueScoped loads the field (which must belong to poolID),
// gates the target user to the same pool, validates the request body against
// the field's type, and upserts the value attributed to actorID. It writes
// the HTTP response itself. Shared by the admin and server APIs, which differ
// only in how they resolve poolID and actorID.
func (handler *RequestHandler) upsertUserFieldValueScoped(w http.ResponseWriter, r *http.Request, poolID, fieldID, userID, actorID uuid.UUID) {
	field, err := handler.repo.GetUserFieldByID(r.Context(), poolID, fieldID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("upsertUserFieldValueScoped: failed to get field")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	user, err := handler.repo.GetUserByID(r.Context(), userID)
	if err != nil || user == nil || user.UserPoolID != poolID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	var req UpsertUserFieldValueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if msg := core.ValidateFieldValue(field.ValueType, req.Value); msg != "" {
		WriteErrorMsg(w, r, msg, http.StatusBadRequest)
		return
	}

	out, err := handler.repo.UpsertUserFieldValue(r.Context(), core.UserFieldValue{
		ID:          utils.NewUUID(),
		UserID:      userID,
		UserFieldID: fieldID,
		UpdatedAt:   time.Now().UTC(),
		UpdatedBy:   actorID,
	}, req.Value)
	if err != nil {
		log.Err(err).Msg("upsertUserFieldValueScoped: upsert failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, UserFieldValueResponse{Value: out}, http.StatusOK)
}

// deleteUserFieldValueScoped clears a user's value for a field after gating
// both the field and the user to poolID. It writes the HTTP response itself.
func (handler *RequestHandler) deleteUserFieldValueScoped(w http.ResponseWriter, r *http.Request, poolID, fieldID, userID uuid.UUID) {
	if _, err := handler.repo.GetUserFieldByID(r.Context(), poolID, fieldID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("deleteUserFieldValueScoped: failed to load field")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	user, err := handler.repo.GetUserByID(r.Context(), userID)
	if err != nil || user == nil || user.UserPoolID != poolID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	if err := handler.repo.DeleteUserFieldValue(r.Context(), fieldID, userID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("deleteUserFieldValueScoped: delete failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (handler *RequestHandler) HandleUpsertUserFieldValue(w http.ResponseWriter, r *http.Request) {
	acc, _, pool, ok := handler.adminAndPool(w, r)
	if !ok {
		return
	}

	fieldID, err := uuid.FromString(chi.URLParam(r, "userFieldId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	userID, err := uuid.FromString(chi.URLParam(r, "userId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	handler.upsertUserFieldValueScoped(w, r, pool.ID, fieldID, userID, acc.ID)
}

func (handler *RequestHandler) HandleDeleteUserFieldValue(w http.ResponseWriter, r *http.Request) {
	_, _, pool, ok := handler.adminAndPool(w, r)
	if !ok {
		return
	}

	fieldID, err := uuid.FromString(chi.URLParam(r, "userFieldId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	userID, err := uuid.FromString(chi.URLParam(r, "userId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	handler.deleteUserFieldValueScoped(w, r, pool.ID, fieldID, userID)
}
