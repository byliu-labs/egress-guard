package drift

import (
	"sort"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

// LearnedPair describes a pair held in the baseline's scoring clouds.
type LearnedPair struct {
	Identity  catalog.Identity `json:"identity"`
	Host      string           `json:"host"`
	FirstSeen time.Time        `json:"first_seen"`
	LastSeen  time.Time        `json:"last_seen"`
	Count     int              `json:"count"`
}

func (b *Baseline) observeLearned(key string, id catalog.Identity, host string, at time.Time) {
	p := b.learned[key]
	if p == nil {
		b.learned[key] = &LearnedPair{Identity: id, Host: host, FirstSeen: at, LastSeen: at, Count: 1}
		return
	}
	if at.Before(p.FirstSeen) {
		p.FirstSeen = at
	}
	if at.After(p.LastSeen) {
		p.LastSeen = at
	}
	p.Count++
}

func (b *Baseline) Learned() []LearnedPair {
	if b == nil {
		return nil
	}
	out := make([]LearnedPair, 0, len(b.learned))
	for _, p := range b.learned {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].FirstSeen.Equal(out[j].FirstSeen) {
			return out[i].FirstSeen.After(out[j].FirstSeen)
		}
		if out[i].Count != out[j].Count {
			return out[i].Count < out[j].Count
		}
		return BaselinePairKeyFor(out[i].Identity, out[i].Host) < BaselinePairKeyFor(out[j].Identity, out[j].Host)
	})
	return out
}

func (b *Baseline) LearnedSince(cut time.Time) []LearnedPair {
	var out []LearnedPair
	for _, p := range b.Learned() {
		if !p.FirstSeen.Before(cut) {
			out = append(out, p)
		}
	}
	return out
}

func learnedFromSlice(pairs []LearnedPair) map[string]*LearnedPair {
	out := make(map[string]*LearnedPair, len(pairs))
	for _, p := range pairs {
		p := p
		out[BaselinePairKeyFor(p.Identity, p.Host)] = &p
	}
	return out
}
