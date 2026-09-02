package reports

// drive_sync.go — Inline drive connector sync implementations
// Supports: Google Drive (OAuth access token), SharePoint (Microsoft Graph),
//           S3 (presigned list URL or public bucket)
// Called by HandleSyncConnectorDocuments in resource_graph.go

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"github.com/ocx/shared/infra/httpclient"
	"net/url"
	"strings"

	"github.com/ocx/shared/infra/database"
)

// upsertDriveDocument inserts or updates a synced document in aocs_tenant_documents.
// Conflict key is (tenant_id, source_id) — source_id is the file ID from the external drive.
// Note: InsertRowIdempotent and UpdateRowCompound do not accept context yet;
// HTTP-level context is handled upstream by the per-drive sync functions.
func upsertDriveDocument(db database.DB, row map[string]any) error {
	// Try insert — ON CONFLICT DO NOTHING for truly new files
	if err := db.InsertRowIdempotent(database.TblTenantDocuments, row, "tenant_id,source_id"); err != nil {
		slog.Debug("drive upsert insert failed, will attempt update", "source_id", row["source_id"], "error", err)
	}
	// Always update in case the file name / URL / status changed
	updates := map[string]any{
		"name":         row["name"],
		"external_url": row["external_url"],
		"status":       "synced",
		"connector_id": row["connector_id"],
	}
	if mime, ok := row["mime_type"].(string); ok {
		updates["mime_type"] = mime
	}
	return db.UpdateRowCompound(database.TblTenantDocuments,
		"tenant_id", fmt.Sprint(row["tenant_id"]),
		"source_id", fmt.Sprint(row["source_id"]),
		updates)
}

// ─── Google Drive ─────────────────────────────────────────────────────────────

// syncGoogleDrive lists files from Google Drive using the stored OAuth access token.
// auth_config: { "access_token": "ya29.xxx", "folder_id": "xxx" (optional) }
func syncGoogleDrive(ctx context.Context, db database.DB, tenantID, connectorID string, connector map[string]any) (int, error) {
	authCfg := parseAuthConfig(connector)
	accessToken, _ := authCfg["access_token"].(string)
	if accessToken == "" {
		return 0, fmt.Errorf("google_drive: no access_token in auth_config — connector not authorized")
	}

	folderID, _ := authCfg["folder_id"].(string)
	displayName, _ := connector["display_name"].(string)

	q := "trashed=false and (mimeType='application/pdf' or mimeType contains 'word' or mimeType='text/plain')"
	if folderID != "" {
		q = fmt.Sprintf("'%s' in parents and %s", folderID, q)
	}
	apiURL := fmt.Sprintf(
		"https://www.googleapis.com/drive/v3/files?fields=files(id,name,mimeType,size,webViewLink,modifiedTime)&q=%s&pageSize=200",
		url.QueryEscape(q),
	)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := httpclient.Shared.Do(req)
	if err != nil {
		return 0, fmt.Errorf("google_drive: API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return 0, fmt.Errorf("google_drive: access token expired — user must re-authorize connector")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("google_drive: API returned %d: %.200s", resp.StatusCode, string(body))
	}

	var driveResp struct {
		Files []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			MimeType    string `json:"mimeType"`
			WebViewLink string `json:"webViewLink"`
		} `json:"files"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&driveResp); err != nil {
		return 0, fmt.Errorf("google_drive: decode failed: %w", err)
	}

	synced := 0
	for _, f := range driveResp.Files {
		row := map[string]any{
			"tenant_id":    tenantID,
			"connector_id": connectorID,
			"source_id":    f.ID,
			"source_type":  "google_drive",
			"name":         f.Name,
			"document_type": mimeToDocType(f.MimeType),
			"mime_type":    f.MimeType,
			"external_url": f.WebViewLink,
			"status":       "synced",
			"description":  fmt.Sprintf("Synced from %s (Google Drive)", displayName),
		}
		if err := upsertDriveDocument(db, row); err != nil {
			slog.Error("google_drive: upsert failed", "file_id", f.ID, "name", f.Name, "error", err)
			continue
		}
		synced++
	}
	return synced, nil
}

// ─── SharePoint ──────────────────────────────────────────────────────────────

// syncSharePoint lists files from a SharePoint document library via Microsoft Graph.
// auth_config: { "access_token": "...", "site_id": "...", "drive_id": "..." (optional) }
func syncSharePoint(ctx context.Context, db database.DB, tenantID, connectorID string, connector map[string]any) (int, error) {
	authCfg := parseAuthConfig(connector)
	accessToken, _ := authCfg["access_token"].(string)
	siteID, _ := authCfg["site_id"].(string)
	driveID, _ := authCfg["drive_id"].(string)
	displayName, _ := connector["display_name"].(string)

	if accessToken == "" || siteID == "" {
		return 0, fmt.Errorf("sharepoint: auth_config requires access_token and site_id")
	}

	graphURL := fmt.Sprintf(
		"https://graph.microsoft.com/v1.0/sites/%s/drive/root/children?$select=id,name,file,webUrl,size,lastModifiedDateTime&$top=200",
		siteID,
	)
	if driveID != "" {
		graphURL = fmt.Sprintf(
			"https://graph.microsoft.com/v1.0/sites/%s/drives/%s/root/children?$select=id,name,file,webUrl,size,lastModifiedDateTime&$top=200",
			siteID, driveID,
		)
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, graphURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := httpclient.Shared.Do(req)
	if err != nil {
		return 0, fmt.Errorf("sharepoint: Graph API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return 0, fmt.Errorf("sharepoint: access token expired — user must re-authorize connector")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("sharepoint: Graph API returned %d: %.200s", resp.StatusCode, string(body))
	}

	var graphResp struct {
		Value []struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			WebURL string `json:"webUrl"`
			File   *struct {
				MimeType string `json:"mimeType"`
			} `json:"file"`
		} `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&graphResp); err != nil {
		return 0, fmt.Errorf("sharepoint: decode failed: %w", err)
	}

	synced := 0
	for _, item := range graphResp.Value {
		if item.File == nil {
			continue // Skip folders
		}
		row := map[string]any{
			"tenant_id":    tenantID,
			"connector_id": connectorID,
			"source_id":    item.ID,
			"source_type":  "sharepoint",
			"name":         item.Name,
			"document_type": mimeToDocType(item.File.MimeType),
			"mime_type":    item.File.MimeType,
			"external_url": item.WebURL,
			"status":       "synced",
			"description":  fmt.Sprintf("Synced from %s (SharePoint)", displayName),
		}
		if err := upsertDriveDocument(db, row); err != nil {
			slog.Error("sharepoint: upsert failed", "item_id", item.ID, "error", err)
			continue
		}
		synced++
	}
	return synced, nil
}

// ─── Amazon S3 ───────────────────────────────────────────────────────────────

// syncS3 lists objects from an S3 bucket.
// auth_config: { "bucket": "...", "region": "...", "presigned_list_url": "..." }
// For private buckets: provide a presigned ListObjectsV2 URL generated server-side.
func syncS3(ctx context.Context, db database.DB, tenantID, connectorID string, connector map[string]any) (int, error) {
	authCfg := parseAuthConfig(connector)
	bucket, _ := authCfg["bucket"].(string)
	region, _ := authCfg["region"].(string)
	prefix, _ := authCfg["prefix"].(string)
	presignedURL, _ := authCfg["presigned_list_url"].(string)
	displayName, _ := connector["display_name"].(string)

	if bucket == "" || region == "" {
		return 0, fmt.Errorf("s3: auth_config requires bucket and region")
	}
	if presignedURL == "" {
		// Public bucket fallback
		presignedURL = fmt.Sprintf(
			"https://%s.s3.%s.amazonaws.com/?list-type=2&prefix=%s&max-keys=500",
			bucket, region, url.QueryEscape(prefix),
		)
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, presignedURL, nil)
	resp, err := httpclient.Shared.Do(req)
	if err != nil {
		return 0, fmt.Errorf("s3: ListObjectsV2 failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("s3: returned %d: %.200s", resp.StatusCode, string(body))
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	synced := 0

	for {
		start := strings.Index(bodyStr, "<Key>")
		end := strings.Index(bodyStr, "</Key>")
		if start == -1 || end == -1 {
			break
		}
		key := bodyStr[start+5 : end]
		bodyStr = bodyStr[end+6:]

		if strings.HasSuffix(key, "/") {
			continue // Skip folder markers
		}
		ext := ""
		if idx := strings.LastIndex(key, "."); idx >= 0 {
			ext = strings.ToLower(key[idx+1:])
		}
		if ext != "pdf" && ext != "docx" && ext != "doc" && ext != "txt" && ext != "xlsx" {
			continue // Only index document files
		}

		name := key
		if idx := strings.LastIndex(key, "/"); idx >= 0 {
			name = key[idx+1:]
		}
		externalURL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", bucket, region, url.PathEscape(key))

		row := map[string]any{
			"tenant_id":    tenantID,
			"connector_id": connectorID,
			"source_id":    key,
			"source_type":  "s3",
			"name":         name,
			"document_type": extToDocType(ext),
			"external_url": externalURL,
			"status":       "synced",
			"description":  fmt.Sprintf("Synced from %s (S3: %s)", displayName, bucket),
		}
		if err := upsertDriveDocument(db, row); err != nil {
			slog.Error("s3: upsert failed", "key", key, "error", err)
			continue
		}
		synced++
	}
	return synced, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// parseAuthConfig extracts auth_config from a connector map, handling both
// map[string]any (from pgx) and JSON string (from Supabase REST) formats.
func parseAuthConfig(connector map[string]any) map[string]any {
	if m, ok := connector["auth_config"].(map[string]any); ok {
		return m
	}
	if raw, ok := connector["auth_config"].(string); ok && raw != "" {
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err == nil {
			return m
		}
	}
	return map[string]any{}
}

func mimeToDocType(mime string) string {
	switch {
	case strings.Contains(mime, "pdf"):
		return "pdf"
	case strings.Contains(mime, "word") || strings.Contains(mime, "docx"):
		return "docx"
	case strings.Contains(mime, "spreadsheet") || strings.Contains(mime, "excel"):
		return "xlsx"
	case strings.Contains(mime, "presentation"):
		return "pptx"
	case strings.Contains(mime, "text"):
		return "txt"
	default:
		return "other"
	}
}

func extToDocType(ext string) string {
	switch ext {
	case "pdf":
		return "pdf"
	case "doc", "docx":
		return "docx"
	case "xls", "xlsx":
		return "xlsx"
	case "ppt", "pptx":
		return "pptx"
	case "txt":
		return "txt"
	default:
		return "other"
	}
}