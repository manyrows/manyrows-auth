package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
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

// importRowPlan is the validated, classified form of one row, carrying the
// resolved ids the apply phase needs so slugs are resolved exactly once.
type importRowPlan struct {
	result    importRowResult
	row       importRow
	roleIDs   []uuid.UUID                   // resolved when row.Roles != nil
	permIDs   []uuid.UUID                   // resolved when row.Permissions != nil
	fieldVals map[uuid.UUID]json.RawMessage // fieldID -> raw value (known keys only)
}

// planRow validates one row and classifies its outcome WITHOUT writing.
// seen tracks normalized emails already encountered in this batch.
func (handler *RequestHandler) planRow(
	ctx context.Context,
	idx int,
	row importRow,
	lk importLookups,
	poolID uuid.UUID,
	onConflict string,
	seen map[string]bool,
) importRowPlan {
	plan := importRowPlan{row: row}
	plan.result.Row = idx + 1
	plan.result.Email = strings.TrimSpace(row.Email)

	fail := func(field, msg string) importRowPlan {
		plan.result.Outcome = "failed"
		plan.result.Errors = append(plan.result.Errors, importFieldError{Field: field, Message: msg})
		return plan
	}

	email := strings.TrimSpace(strings.ToLower(row.Email))
	if _, err := mail.ParseAddress(email); err != nil {
		return fail("email", "invalid email format")
	}
	plan.result.Email = email

	if seen[email] {
		return fail("email", "duplicate email in file")
	}
	seen[email] = true

	if row.Roles != nil {
		ids, unknown := resolveSlugs(*row.Roles, lk.roleBySlug)
		if len(unknown) > 0 {
			return fail("roles", "unknown role(s): "+strings.Join(unknown, ", "))
		}
		plan.roleIDs = ids
	}
	if row.Permissions != nil {
		ids, unknown := resolveSlugs(*row.Permissions, lk.permBySlug)
		if len(unknown) > 0 {
			return fail("permissions", "unknown permission(s): "+strings.Join(unknown, ", "))
		}
		plan.permIDs = ids
	}
	if row.Fields != nil {
		plan.fieldVals = map[uuid.UUID]json.RawMessage{}
		for key, raw := range row.Fields {
			field, ok := lk.fieldByKey[key]
			if !ok {
				return fail("fields."+key, "unknown field key")
			}
			if msg := core.ValidateFieldValue(field.ValueType, raw); msg != "" {
				return fail("fields."+key, msg)
			}
			plan.fieldVals[field.ID] = raw
		}
	}

	// Existence classification (read-only).
	existing, err := handler.repo.GetUserByEmailInPool(ctx, email, poolID)
	if err != nil && !errors.Is(err, repo.ErrNotFound) {
		return fail("", "internal error")
	}
	switch {
	case existing == nil:
		plan.result.Outcome = "created"
	case onConflict == "update":
		plan.result.Outcome = "updated"
		plan.result.UserID = existing.ID.String()
	default:
		plan.result.Outcome = "skipped"
		plan.result.UserID = existing.ID.String()
	}
	return plan
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

	seen := make(map[string]bool, len(req.Rows))
	plans := make([]importRowPlan, 0, len(req.Rows))
	for i, row := range req.Rows {
		plans = append(plans, handler.planRow(ctx, i, row, lk, app.UserPoolID, onConflict, seen))
	}

	results := make([]importRowResult, 0, len(plans))
	for _, plan := range plans {
		// Apply phase (Task 3) handles created/updated rows. For now, and
		// always for dryRun, return the classification as-is.
		results = append(results, plan.result)
	}

	resp := bulkImportResponse{DryRun: req.DryRun, Rows: results, Summary: summarize(results)}
	utils.WriteJsonWithStatusCode(w, resp, http.StatusOK)
}
