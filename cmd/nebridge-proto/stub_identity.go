//go:build nebridge_testing

package main

import (
	"flag"

	"github.com/byliu-labs/egress-guard/internal/nebridge"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

func registerStubIdentity(fs *flag.FlagSet) func() nebridge.IdentityResolver {
	on := fs.Bool("test-stub-identity", false, "replace audit-token identity with a fixed fake (testing builds only)")
	return func() nebridge.IdentityResolver {
		if !*on {
			return nil
		}
		return nebridge.StubResolver{
			Proc: procid.ProcInfo{Comm: "nebridge-proto-test"},
			Sig:  signature.SignedIdentity{Valid: true, TeamID: "TESTTEAM"},
		}
	}
}
