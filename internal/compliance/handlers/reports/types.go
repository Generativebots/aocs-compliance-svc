// Package analytics — named request and row types.
package reports

// AnalyticsQueryRequest is the body for POST /analytics/query.
type AnalyticsQueryRequest struct {
	Metric    string `json:"metric"`
	StartDate string `json:"start_date,omitempty"`
	EndDate   string `json:"end_date,omitempty"`
	AgentID   string `json:"agent_id,omitempty"`
}

// PolicyBindingRequest is the body for POST /analytics/policy-bindings.
type PolicyBindingRequest struct {
	AgentID	string	`json:"agent_id" validate:"required"`
	PolicyID	string	`json:"policy_id" validate:"required"`
	PolicyVersion int    `json:"policy_version"`
	BindingType   string `json:"binding_type"`
	BoundBy       string `json:"bound_by"`
}

// TokenRevokeRequest is the body for POST /analytics/tokens/:id/revoke.
type TokenRevokeRequest struct {
	TokenID string `json:"token_id"`
}

// DashboardRow is the DB projection for dashboard metric reads.
type DashboardRow struct {
	MetricName  string  `json:"metric_name"`
	MetricValue float64 `json:"metric_value"`
	Period      string  `json:"period"`
	AgentID     string  `json:"agent_id,omitempty"`
}

// KPIRow is the DB projection for KPI reads.
type KPIRow struct {
	KPIID  string  `json:"kpi_id"`
	Name   string  `json:"name"`
	Value  float64 `json:"value"`
	Target float64 `json:"target"`
	Period string  `json:"period"`
}

// MetricsRow is the DB projection for metrics reads.
type MetricsRow struct {
	Timestamp  string  `json:"timestamp"`
	MetricName string  `json:"metric_name"`
	Value      float64 `json:"value"`
	Tags       string  `json:"tags,omitempty"`
}

// UpdateEvidenceRequest is the request body for HandleUpdateEvidence. (3 fields)
type UpdateEvidenceRequest struct {
	Type	string	`json:"type" validate:"required"`
	ActionClass string         `json:"action_class"`
	PayloadData map[string]any `json:"payload_data"`
}

// UpsertOgraphFlowRequest is the request body for HandleUpsertOgraphFlow. (4 fields)
type UpsertOgraphFlowRequest struct {
	SourceNode string  `json:"source_node"`
	TargetNode string  `json:"target_node"`
	FlowValue  float64 `json:"flow_value"`
	FlowType   string  `json:"flow_type"`
}

// UpdateImportSourceRequest is the request body for HandleUpdateImportSource. (4 fields)
type UpdateImportSourceRequest struct {
	Name	string	`json:"name" validate:"required"`
	SourceType string         `json:"source_type"`
	Config     map[string]any `json:"config"`
	Status	string	`json:"status" validate:"required"`
}

// BindPolicyRequest is the request body for HandleBindPolicy. (5 fields)
type BindPolicyRequest struct {
	AgentID	string	`json:"agent_id" validate:"required"`
	PolicyID	string	`json:"policy_id" validate:"required"`
	PolicyVersion int    `json:"policy_version"`
	BindingType   string `json:"binding_type"`
	BoundBy       string `json:"bound_by"`
}

// AnalyticsQueryRequest2 is the request body for HandleGetAnalyticsQuery. (4 fields)
type AnalyticsQueryRequest2 struct {
	Metric    string `json:"metric"`
	StartDate string `json:"start_date"`
	EndDate   string `json:"end_date"`
	AgentID   string `json:"agent_id"`
}
