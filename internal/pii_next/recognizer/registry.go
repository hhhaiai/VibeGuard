package recognizer

// Registry manages a set of Recognizers.
type Registry struct {
	recognizers []Recognizer
}

func NewRegistry(recognizers ...Recognizer) *Registry {
	r := &Registry{}
	r.Add(recognizers...)
	return r
}

func (r *Registry) Add(recognizers ...Recognizer) {
	for _, rec := range recognizers {
		if rec == nil {
			continue
		}
		r.recognizers = append(r.recognizers, rec)
	}
}

func (r *Registry) RecognizeAll(input []byte) []Match {
	var out []Match
	for _, rec := range r.recognizers {
		matches := rec.Recognize(input)
		if len(matches) == 0 {
			continue
		}
		out = append(out, matches...)
	}
	return out
}
