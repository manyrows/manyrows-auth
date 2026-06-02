package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"manyrows-core/core"

	"github.com/rs/zerolog/log"
)

// SupportedLanguages is the list of supported language codes for i18n.
// Keep in sync with the UI i18n locales and the api/email translation catalogs.
var SupportedLanguages = []string{"en", "ko"}

type updateNameReq struct {
	Name string `json:"name"`
}

func (handler *RequestHandler) UpdateAccountName(w http.ResponseWriter, r *http.Request) {
	acc, ok := core.AdminAccountFromContext(r.Context())
	if !ok || acc == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	var req updateNameReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode update account name request")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		WriteError(w, r, "error.nameRequired", http.StatusBadRequest)
		return
	}

	cur := acc.Name

	if strings.TrimSpace(cur) == name {
		w.WriteHeader(http.StatusOK)
		return
	}

	if err := handler.repo.UpdateName(r.Context(), acc.ID, name); err != nil {
		if errors.Is(err, core.ErrAccountNotFound) {
			WriteError(w, r, "error.accountNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to update account name")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

type updateLanguageReq struct {
	Language string `json:"language"`
}

func (handler *RequestHandler) UpdateAccountLanguage(w http.ResponseWriter, r *http.Request) {
	acc, ok := core.AdminAccountFromContext(r.Context())
	if !ok || acc == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	var req updateLanguageReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode update language request")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	lang := strings.TrimSpace(strings.ToLower(req.Language))
	if !slices.Contains(SupportedLanguages, lang) {
		WriteError(w, r, "error.languageInvalid", http.StatusBadRequest)
		return
	}

	if acc.Language == lang {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := handler.repo.UpdateAccountLanguage(r.Context(), acc.ID, lang); err != nil {
		if errors.Is(err, core.ErrAccountNotFound) {
			WriteError(w, r, "error.accountNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to update account language")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
