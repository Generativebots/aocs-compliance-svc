package compliance

// Policy violation types recorded in compl_policy_violations.violation_type.
// Continuous compliance links each type to the controls it undermines.
const (
	// ViolationTypeDLPExfiltration is recorded when DLP blocks an agent prompt or response.
	ViolationTypeDLPExfiltration = "DLP_EXFILTRATION"
	// ViolationTypeGateBlock is a gate BLOCK verdict (refused agent action),
	// harvested from the gate decision log (GX-15).
	ViolationTypeGateBlock = "GATE_BLOCK"
	// ViolationTypeGateEscalation is a gate ESC verdict (action held for a
	// human), harvested from the gate decision log (GX-15).
	ViolationTypeGateEscalation = "GATE_ESCALATION"
)
