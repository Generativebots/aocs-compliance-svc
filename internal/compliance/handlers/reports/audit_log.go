package reports

// auditPageSize is the number of events per page.
// Chosen to balance perceived latency (first byte) vs round-trips.
const auditPageSize = 50
