package ahocorasick

// Matcher is an Aho-Corasick automaton for multi-pattern matching over exact string patterns.
//
// Design goals:
// - lightweight: no third-party dependencies
// - byte-oriented: match on UTF-8 byte sequences (works for multilingual text)
// - reusable: read-only after build; safe for concurrent matching
//
// Notes:
// - pattern order determines match IDs (0..n-1)
// - this implementation does not perform case/Unicode normalization; callers should normalize patterns as needed
type Matcher struct {
	nodes []node
	lens  []int // pattern byte length by id
}

type node struct {
	next map[byte]int
	fail int
	out  []int // pattern ids that end at this node (includes failure outputs)
}

// New builds an automaton from patterns. Empty patterns are ignored.
func New(patterns []string) *Matcher {
	m := &Matcher{}
	m.build(patterns)
	return m
}

func (m *Matcher) build(patterns []string) {
	m.nodes = nil
	m.lens = nil

	if len(patterns) == 0 {
		return
	}

	// root
	m.nodes = append(m.nodes, node{next: make(map[byte]int)})
	m.lens = make([]int, len(patterns))

	// 1) build trie
	for id, pat := range patterns {
		if pat == "" {
			continue
		}
		m.lens[id] = len(pat)

		cur := 0
		for i := 0; i < len(pat); i++ {
			b := pat[i]
			nxt, ok := m.nodes[cur].next[b]
			if !ok {
				nxt = len(m.nodes)
				m.nodes[cur].next[b] = nxt
				m.nodes = append(m.nodes, node{next: make(map[byte]int)})
			}
			cur = nxt
		}
		m.nodes[cur].out = append(m.nodes[cur].out, id)
	}

	// 2) build failure links (BFS)
	q := make([]int, 0, len(m.nodes))
	for _, child := range m.nodes[0].next {
		m.nodes[child].fail = 0
		q = append(q, child)
	}

	for head := 0; head < len(q); head++ {
		v := q[head]
		for b, u := range m.nodes[v].next {
			q = append(q, u)

			f := m.nodes[v].fail
			for f != 0 {
				if w, ok := m.nodes[f].next[b]; ok {
					m.nodes[u].fail = w
					goto linked
				}
				f = m.nodes[f].fail
			}

			if w, ok := m.nodes[0].next[b]; ok {
				m.nodes[u].fail = w
			} else {
				m.nodes[u].fail = 0
			}

		linked:
			// Output merge: include failure node outputs so matching does not need to walk the fail chain.
			if f := m.nodes[u].fail; f != 0 && len(m.nodes[f].out) > 0 {
				m.nodes[u].out = append(m.nodes[u].out, m.nodes[f].out...)
			}
		}
	}
}

// PatternCount returns the number of patterns (ID range: 0..PatternCount-1).
func (m *Matcher) PatternCount() int {
	if m == nil {
		return 0
	}
	return len(m.lens)
}

// EachMatch matches over input and calls fn for each hit.
// Returning false from fn stops iteration early.
func (m *Matcher) EachMatch(input []byte, fn func(id, start, end int) bool) {
	if m == nil || len(m.nodes) == 0 || len(input) == 0 || fn == nil {
		return
	}

	state := 0
	for i := 0; i < len(input); i++ {
		b := input[i]

		// Transition; if missing, follow fail links back until root.
		for state != 0 {
			if nxt, ok := m.nodes[state].next[b]; ok {
				state = nxt
				goto matched
			}
			state = m.nodes[state].fail
		}
		if nxt, ok := m.nodes[0].next[b]; ok {
			state = nxt
		} else {
			state = 0
		}

	matched:
		if len(m.nodes[state].out) == 0 {
			continue
		}
		end := i + 1
		for _, id := range m.nodes[state].out {
			l := 0
			if id >= 0 && id < len(m.lens) {
				l = m.lens[id]
			}
			if l <= 0 || l > end {
				continue
			}
			start := end - l
			if start < 0 || start >= end {
				continue
			}
			if !fn(id, start, end) {
				return
			}
		}
	}
}

// EachMatchNonOverlappingPerPattern is like EachMatch, but guarantees that hits for the same pattern do not overlap.
//
// This preserves historical behavior: when scanning one keyword at a time via bytes.Index, hits are leftmost-first and non-overlapping.
//
// lastEndScratch avoids frequent allocations; if nil or too short, it is allocated internally.
func (m *Matcher) EachMatchNonOverlappingPerPattern(input []byte, lastEndScratch []int, fn func(id, start, end int) bool) {
	if m == nil || len(m.nodes) == 0 || len(input) == 0 || fn == nil {
		return
	}

	patN := len(m.lens)
	lastEnd := lastEndScratch
	if lastEnd == nil || len(lastEnd) < patN {
		lastEnd = make([]int, patN)
	} else {
		clear(lastEnd[:patN])
	}

	m.EachMatch(input, func(id, start, end int) bool {
		if id < 0 || id >= patN {
			return true
		}
		if start < lastEnd[id] {
			return true
		}
		lastEnd[id] = end
		return fn(id, start, end)
	})
}
