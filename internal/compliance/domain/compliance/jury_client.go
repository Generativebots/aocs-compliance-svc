// Package jury provides a Go gRPC client for the Python Jury Auditor service.
//
// Jury unavailable now returns "DENY" (fail-closed), not "UNKNOWN".
// "UNKNOWN" was a third state that the TFG gate and Escrow FSM had no handler for:
// - TFG: only checked ALLOW/DENY, so UNKNOWN fell through → escrow stayed HELD forever.
// - Escrow: no timeout/sweep for stuck HELD records → funds frozen permanently.
// Fail-closed is the correct security posture: if we cannot verify, we deny.
package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/ocx/shared/infra/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// JuryClient wraps a gRPC connection to the Python Jury Auditor service.
type JuryClient struct {
	conn   *grpc.ClientConn
	addr   string
	logger *slog.Logger
}

// NewJuryClient dials the Jury gRPC service at addr.
// If addr is empty, it returns an error — callers must configure JURY_GRPC_ADDR.
// Uses security.Dial for OTEL instrumentation + keepalive + retry policy
// (WIRE-GAP-09: prevents idle-timeout DENY storms after cold-start).
func NewJuryClient(addr string) (*JuryClient, error) {
	if addr == "" {
		// P0-fix: no localhost fallback — in Cloud Run, localhost:50090 is unreachable.
		// Set JURY_GRPC_ADDR (or cfg.Services.JuryGRPCAddr) to the service's internal URL.
		return nil, fmt.Errorf("jury gRPC address not configured — set JURY_GRPC_ADDR env var")
	}

	// P3-fix: grpc.DialContext + grpc.WithBlock are deprecated since gRPC-Go 1.64.
	// security.Dial uses grpc.NewClient (non-blocking) with keepalive + OTEL + retry.
	conn, err := security.Dial(addr)
	if err != nil {
		return nil, fmt.Errorf("jury gRPC client creation failed (%s): %w", addr, err)
	}

	return &JuryClient{
		conn:   conn,
		addr:   addr,
		logger: slog.Default().With("component", "jury-client"),
	}, nil
}

// Close shuts down the gRPC connection.
func (jc *JuryClient) Close() error {
	if jc.conn != nil {
		return jc.conn.Close()
	}
	return nil
}

// AuditIntent sends a unary audit request to the Python Jury.
// tenantID is propagated as x-tenant-id gRPC metadata (FA-47) so the Python
// TenantPropagationInterceptor can enforce tenant isolation at the gRPC layer.
// Returns the verdict, confidence, reason, and any error.
//
// If the Jury is unreachable, returns fail-closed DENY verdict.
func (jc *JuryClient) AuditIntent(
	ctx context.Context,
	tenantID, txID, agentID, toolName string,
	intentID, departmentID string,
	params map[string]any,
) (*AuditResponse, error) {
	req := &AuditRequest{
		TransactionID: txID,
		AgentID:       agentID,
		ToolName:      toolName,
		Parameters:    params,
		// G2 FIX: intent-scoped ML policy rules require intentID and departmentID.
		Context: map[string]any{
			"intent_id":     intentID,
			"department_id": departmentID,
		},
	}

	if tenantID != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "x-tenant-id", tenantID)
	}
	// M6 FIX: Forward X-Request-ID into gRPC metadata for distributed trace correlation.
	// The request ID is set by gateway-client.ts on every request and echoed by NGINX.
	// Forwarding it here closes the Go → Python gRPC trace gap.
	if reqID, ok := ctx.Value("x-request-id").(string); ok && reqID != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "x-request-id", reqID)
	}

	// Serialize to JSON (matching Python proto stub wire format)
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal audit request: %w", err)
	}

	// Call the unary RPC
	var respBytes []byte
	err = jc.conn.Invoke(ctx, "/ocx.jury.JuryAuditor/AuditIntent", reqBytes, &respBytes)
	if err != nil {
		jc.logger.Warn("Jury AuditIntent RPC failed — fail-closed with DENY",
			"error", err, "addr", jc.addr, "tx_id", txID)
		// Return DENY not UNKNOWN. UNKNOWN has no handler in TFG/Escrow FSM
		// and causes escrow to stay HELD indefinitely (funds frozen).
		return &AuditResponse{
			TransactionID: txID,
			Verdict:       "DENY",
			Confidence:    0,
			Reason:        "jury_unavailable: fail-closed",
			IsFallback:    true,
		}, nil
	}

	var resp AuditResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal audit response: %w", err)
	}

	jc.logger.Info("Jury verdict received",
		"tx_id", txID, "verdict", resp.Verdict, "confidence", resp.Confidence)

	return &resp, nil
}

// TryAuditIntent attempts to create a client, audit, and close in one shot.
// tenantID is passed to AuditIntent for FA-47 gRPC metadata propagation.
// intentID and departmentID are passed for G2 FIX intent-scoped ML policy rules.
// Returns graceful fallback on connection failure.
func TryAuditIntent(
	ctx context.Context,
	addr, tenantID, txID, agentID, toolName string,
	intentID, departmentID string,
	params map[string]any,
) *AuditResponse {
	client, err := NewJuryClient(addr)
	if err != nil {
		slog.Error("Jury unavailable — fail-closed with DENY",
			"addr", addr, "error", err)
		// Fail-closed
		return &AuditResponse{
			TransactionID: txID,
			Verdict:       "DENY",
			Confidence:    0,
			Reason:        "jury_unavailable: fail-closed",
			IsFallback:    true,
		}
	}
	defer client.Close()

	resp, err := client.AuditIntent(ctx, tenantID, txID, agentID, toolName, intentID, departmentID, params)
	if err != nil {
		return &AuditResponse{
			TransactionID: txID,
			Verdict:       "DENY",
			Confidence:    0,
			Reason:        fmt.Sprintf("audit_error (fail-closed): %v", err),
			IsFallback:    true,
		}
	}
	return resp
}
