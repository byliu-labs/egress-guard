package decisionlog

// Joined is a decision record and, when the connection spliced and closed,
// its corresponding flow record. Missing flow metadata is unknown, not zero.
type Joined struct {
	Decision Entry
	Flow     Entry
	HasFlow  bool
}

// Join correlates decisions and flow records by ConnID while preserving the
// decision order. Orphan flow records are ignored and later flows replace
// earlier flows for the same connection.
func Join(entries []Entry) []Joined {
	out := make([]Joined, 0, len(entries))
	index := make(map[string]int, len(entries))
	for _, entry := range entries {
		if !entry.IsFlow() {
			out = append(out, Joined{Decision: entry})
			if entry.ConnID != "" {
				index[entry.ConnID] = len(out) - 1
			}
			continue
		}
		if i, ok := index[entry.ConnID]; entry.ConnID != "" && ok {
			out[i].Flow = entry
			out[i].HasFlow = true
		}
	}
	return out
}
