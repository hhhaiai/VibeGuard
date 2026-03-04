package redact

// Redactor is the minimal interface for a redaction engine (used by the proxy to switch implementations).
//
// Contract: implementations must populate matches with Original/Placeholder for audit display and later restore.
type Redactor interface {
	RedactWithMatches(input []byte) (out []byte, matches []Match)
}
