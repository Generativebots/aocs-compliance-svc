package compliance

// Policy violation types recorded in compl_policy_violations.violation_type.
// Continuous compliance links each type to the controls it undermines.
const (
	// ViolationTypeDLPExfiltration is recorded when DLP blocks an agent prompt or response.
	ViolationTypeDLPExfiltration = "DLP_EXFILTRATION"
)
