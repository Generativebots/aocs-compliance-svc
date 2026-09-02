package compliance

import (
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// HandleAdminListAuthorityGaps returns all authority gaps for the caller's tenant.
// GET /authority-gaps
func HandleAdminListAuthorityGaps(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		gaps, err := db.ListAuthorityGaps(tenantID)
		if err != nil {
			if err == database.ErrPoolUnavailable {
				// FALLBACK: pgx not ready — use REST API for authority gaps.
				slog.Warn("HandleAdminListAuthorityGaps: pgx unavailable — REST fallback", "tenant_id", tenantID)
				var rawRows []map[string]any
				restErr := db.QueryRows(
					database.TblIAAuthorityGaps,
					"gap_id,tenant_id,agent_id,gap_type,description,severity,status,created_at",
					"tenant_id",
					tenantID,
					&rawRows,
				)
				if restErr != nil {
					slog.Error("HandleAdminListAuthorityGaps: REST fallback failed", "tenant_id", tenantID, "error", restErr)
					respond.InternalError(w, http.StatusInternalServerError, "Failed to list authority gaps:", restErr)
					return
				}
				respond.JSON(w, http.StatusOK, map[string]any{
					"gaps":  rawRows,
					"total": len(rawRows),
				})
				return
			}
			respond.InternalError(w, http.StatusInternalServerError, "Failed to list authority gaps:", err)
			return
		}
		respond.JSON(w, http.StatusOK, map[string]any{
			"gaps":  gaps,
			"total": len(gaps),
		})
	}
}

// HandleGetAuthorityGap returns a single authority gap by ID.
// GET /ia/authority/gaps/{id}
func HandleGetAuthorityGap(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		gapID := mux.Vars(r)["id"]
		if gapID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "Missing gap ID")
			return
		}

		gap, err := db.GetAuthorityGap(tenantID, gapID)
		if err != nil {
			slog.Error("GetAuthorityGap failed", "tenant_id", tenantID, "gap_id", gapID, "error", err)
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "authority gap not found")
			return
		}
		respond.JSON(w, http.StatusOK, gap)
	}
}

// HandleAdminListAuthorityContracts returns all deployed authority contracts for the tenant.
// GET /ia/authority/contracts
func HandleAdminListAuthorityContracts(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		contracts, err := db.ListAuthorityContracts(tenantID)
		if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "Failed to list authority contracts:", err)
			return
		}
		respond.JSON(w, http.StatusOK, map[string]any{
			"contract_records": contracts,
			"total":     len(contracts),
		})
	}
}

// HandleAdminGetAuthorityContract returns a single authority contract by ID.
// GET /ia/authority/contracts/{id}
func HandleAdminGetAuthorityContract(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		contractID := mux.Vars(r)["id"]
		if contractID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "Missing contract ID")
			return
		}

		contract, err := db.GetAuthorityContract(tenantID, contractID)
		if err != nil {
			slog.Error("GetAuthorityContract failed", "tenant_id", tenantID, "contract_id", contractID, "error", err)
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "authority contract not found")
			return
		}
		respond.JSON(w, http.StatusOK, contract)
	}
}

// HandleAdminListParsedDocuments returns all documents parsed by the Python APE service.
// GET /ia/authority/documents
func HandleAdminListParsedDocuments(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		docs, err := db.ListParsedDocuments(tenantID)
		if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "Failed to list parsed documents:", err)
			return
		}
		respond.JSON(w, http.StatusOK, map[string]any{
			"documents": docs,
			"total":     len(docs),
		})
	}
}

// HandleAdminGetParsedDocument returns a single parsed document record by ID.
// GET /ia/authority/documents/{id}
func HandleAdminGetParsedDocument(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		docID := mux.Vars(r)["id"]
		if docID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "Missing document ID")
			return
		}

		doc, err := db.GetParsedDocument(tenantID, docID)
		if err != nil {
			slog.Error("GetParsedDocument failed", "tenant_id", tenantID, "doc_id", docID, "error", err)
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "parsed document not found")
			return
		}
		respond.JSON(w, http.StatusOK, doc)
	}
}
