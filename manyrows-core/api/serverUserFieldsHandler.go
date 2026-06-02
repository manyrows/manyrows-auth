package api

import (
	"net/http"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

// GET /x/{workspaceSlug}/api/v1/apps/{appId}/user-fields
func (handler *RequestHandler) HandleServerGetUserFields(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, ok := core.WorkspaceFromContext(ctx)
	if !ok {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	fields, err := handler.repo.GetUserFieldsByUserPoolID(ctx, app.UserPoolID)
	if err != nil {
		log.Err(err).Msg("HandleServerGetUserFields: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, UserFieldsResponse{UserFields: fields}, http.StatusOK)
}

// GET /x/{workspaceSlug}/api/v1/apps/{appId}/user-fields/users/{userId}
func (handler *RequestHandler) HandleServerGetUserFieldValues(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, ok := core.WorkspaceFromContext(ctx)
	if !ok {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}

	// Server API scopes to app membership; the pool only shares credentials.
	// A non-member (incl. a foreign-pool id) gets 404 here.
	if !handler.requireAppMember(w, r, app.ID, userID) {
		return
	}

	values, err := handler.repo.GetUserFieldValuesByUser(ctx, userID)
	if err != nil {
		log.Err(err).Msg("HandleServerGetUserFieldValues: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, UserFieldValuesResponse{Values: values}, http.StatusOK)
}
