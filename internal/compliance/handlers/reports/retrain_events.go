// retrain_events.go — NULL retrain completed_at FIX
//
// Provides two endpoints for the ML training lifecycle:
//
//	GET  /analytics/retrain-events
//	  Lists all platform events with trigger_source=HUMAN_ARBITRATION (RLHC retrain queue).
//	  Returns events with pending_count and training status.
//
//	PATCH /analytics/retrain-events/{id}/complete
//	  Called by the Python Vertex AI worker when a training job finishes.
//	  Writes completed_at + model_version to the core_events row.
//	  This fixes the always-NULL completed_at field on retrain records.
package reports
