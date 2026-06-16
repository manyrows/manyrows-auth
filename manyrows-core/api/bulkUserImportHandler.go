package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// maxImportRows caps rows per request. The root router also enforces a 1 MB
// request-body limit (app/router.go), so field-heavy imports can hit that
// ceiling before 1000 rows — those requests return 413, not a silent truncation.
const maxImportRows = 1000

// importRow is one user entry in an import request. Pointer/map fields let us
// distinguish "key absent" (leave unchanged on update) from "present but empty"
// (explicitly clear). See the design's present-vs-absent table.
type importRow struct {
	Email         string                     `json:"email"`
	Enabled       *bool                      `json:"enabled"`
	EmailVerified *bool                      `json:"emailVerified"`
	Roles         *[]string                  `json:"roles"`
	Permissions   *[]string                  `json:"permissions"`
	Fields        map[string]json.RawMessage `json:"fields"`
}

type bulkImportRequest struct {
	OnConflict   string      `json:"onConflict"` // "skip" (default) | "update"
	DryRun       bool        `json:"dryRun"`
	DefaultRoles []string    `json:"defaultRoles"`
	SendInvite   bool        `json:"sendInvite"`
	Rows         []importRow `json:"rows"`
}

type importFieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

type importRowResult struct {
	Row      int                `json:"row"`
	Email    string             `json:"email"`
	Outcome  string             `json:"outcome"` // created|updated|skipped|failed
	UserID   string             `json:"userId,omitempty"`
	Errors   []importFieldError `json:"errors,omitempty"`
	Warnings []string           `json:"warnings,omitempty"`
}

type importSummary struct {
	Total   int `json:"total"`
	Created int `json:"created"`
	Updated int `json:"updated"`
	Skipped int `json:"skipped"`
	Failed  int `json:"failed"`
}

type bulkImportResponse struct {
	DryRun  bool              `json:"dryRun"`
	Summary importSummary     `json:"summary"`
	Rows    []importRowResult `json:"rows"`
}

// importLookups holds project/pool reference data resolved once per batch.
type importLookups struct {
	roleBySlug map[string]uuid.UUID
	permBySlug map[string]uuid.UUID
	fieldByKey map[string]core.UserField
}

// resolveSlugs maps slugs to ids via bySlug, collecting any unknown slugs.
func resolveSlugs(slugs []string, bySlug map[string]uuid.UUID) (ids []uuid.UUID, unknown []string) {
	for _, s := range slugs {
		if id, ok := bySlug[s]; ok {
			ids = append(ids, id)
		} else {
			unknown = append(unknown, s)
		}
	}
	return ids, unknown
}

func (handler *RequestHandler) loadImportLookups(ctx context.Context, projectID, poolID uuid.UUID) (importLookups, error) {
	lk := importLookups{
		roleBySlug: map[string]uuid.UUID{},
		permBySlug: map[string]uuid.UUID{},
		fieldByKey: map[string]core.UserField{},
	}
	roles, err := handler.repo.GetRolesByProjectID(ctx, projectID)
	if err != nil {
		return lk, err
	}
	for _, role := range roles {
		lk.roleBySlug[role.Slug] = role.ID
	}
	perms, err := handler.repo.GetPermissionsByProjectID(ctx, projectID)
	if err != nil {
		return lk, err
	}
	for _, p := range perms {
		lk.permBySlug[p.Slug] = p.ID
	}
	fields, err := handler.repo.GetUserFieldsByUserPoolID(ctx, poolID)
	if err != nil {
		return lk, err
	}
	for _, f := range fields {
		lk.fieldByKey[f.Key] = f
	}
	return lk, nil
}

func summarize(rows []importRowResult) importSummary {
	s := importSummary{Total: len(rows)}
	for _, r := range rows {
		switch r.Outcome {
		case "created":
			s.Created++
		case "updated":
			s.Updated++
		case "skipped":
			s.Skipped++
		case "failed":
			s.Failed++
		}
	}
	return s
}

// HandleAdminBulkUserImport imports/updates many users in one request.
// POST /admin/workspace/{workspaceId}/projects/{projectId}/apps/{appId}/users:import
func (handler *RequestHandler) HandleAdminBulkUserImport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	acc, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	_ = acc // used in the apply phase (Task 3)

	projectID, err := utils.GetPathUUID("projectId", r)
	if err != nil || projectID == uuid.Nil {
		WriteError(w, r, "error.invalidProjectId", http.StatusBadRequest)
		return
	}
	appID, err := utils.GetPathUUID("appId", r)
	if err != nil || appID == uuid.Nil {
		WriteError(w, r, "error.invalidAppId", http.StatusBadRequest)
		return
	}
	// Validates the app belongs to (workspace, project) and returns it; gives
	// us app.ProjectID and app.UserPoolID for slug/field resolution.
	app, err := handler.repo.GetAppByIDForProject(ctx, ws.ID, projectID, appID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Msg("bulk import: failed to load app")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	var req bulkImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			WriteErrorMsg(w, r, "import payload too large; split into smaller batches", http.StatusRequestEntityTooLarge)
			return
		}
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	onConflict := req.OnConflict
	if onConflict == "" {
		onConflict = "skip"
	}
	if onConflict != "skip" && onConflict != "update" {
		WriteErrorMsg(w, r, "onConflict must be 'skip' or 'update'", http.StatusBadRequest)
		return
	}
	if len(req.Rows) > maxImportRows {
		WriteErrorMsg(w, r, "maximum 1000 rows per request", http.StatusBadRequest)
		return
	}

	lk, err := handler.loadImportLookups(ctx, projectID, app.UserPoolID)
	if err != nil {
		log.Error().Err(err).Msg("failed to load import lookups")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Batch-level default roles. Unknown slugs here are a configuration error
	// affecting every row, so fail the whole request.
	defaultRoleIDs, unknownDefaults := resolveSlugs(req.DefaultRoles, lk.roleBySlug)
	if len(unknownDefaults) > 0 {
		WriteErrorMsg(w, r, "unknown default role(s): "+strings.Join(unknownDefaults, ", "), http.StatusBadRequest)
		return
	}
	_ = defaultRoleIDs // used in the apply phase (Task 3)

	// Row processing is added in Task 2 (validate) and Task 3 (apply).
	results := make([]importRowResult, 0, len(req.Rows))
	resp := bulkImportResponse{DryRun: req.DryRun, Rows: results, Summary: summarize(results)}
	utils.WriteJsonWithStatusCode(w, resp, http.StatusOK)
}
