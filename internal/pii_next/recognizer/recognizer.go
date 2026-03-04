package recognizer

// Match represents a hit range (byte offsets, half-open [Start, End)).
//
// Higher Priority wins: when multiple rules overlap, the pipeline keeps higher-priority matches
// and drops lower-priority ones (instead of fragmenting large matches), avoiding accidental replacement of non-sensitive fragments.
type Match struct {
	Start    int
	End      int
	Category string
	Priority int
	Source   string
}

// Recognizer detects sensitive fragments in input.
// Returned matches must satisfy:
// - 0 <= Start < End <= len(input)
// - Start/End are byte offsets (do not use rune indices)
type Recognizer interface {
	Name() string
	Recognize(input []byte) []Match
}
