// Package handlers — Resource Graph API for the JARVIS Mind-Map Dashboard.
//
// Integration-first architecture:
//   import_sources (KB/BPM/SOP refs) → aocs_tenant_documents → intent_mappings → resource_relationships
//   GRA trust_attestations govern intents and agt.

package reports

type GraphNode struct {
	ID       string      `json:"id"`
	Type     string      `json:"type"`
	Label    string      `json:"label"`
	Status   string      `json:"status,omitempty"`
	Risk     string      `json:"risk,omitempty"`
	Metadata interface{} `json:"metadata,omitempty"`
}
type GraphEdge struct {
	Source string  `json:"source"`
	Target string  `json:"target"`
	Type   string  `json:"type"`
	Weight float64 `json:"weight"`
}
