package cli

import (
	"github.com/byliu-labs/egress-guard/internal/drift"
	"github.com/byliu-labs/egress-guard/internal/rejected"
)

type rejectionAdapter struct{ s *rejected.Store }

func (a rejectionAdapter) Contains(base, sha, team, host string) bool {
	return a.s.Contains(rejected.Key{ExeBasename: base, ExeSHA256: sha, TeamID: team, Host: host})
}
func (a rejectionAdapter) Digest() string { return a.s.Digest() }
func rejectionDigest(r interface{ Digest() string }) string {
	if r == nil {
		return drift.EmptyRejectionDigest
	}
	return r.Digest()
}
