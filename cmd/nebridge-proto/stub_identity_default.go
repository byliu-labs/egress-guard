//go:build !nebridge_testing

package main

import (
	"flag"

	"github.com/byliu-labs/egress-guard/internal/nebridge"
)

func registerStubIdentity(*flag.FlagSet) func() nebridge.IdentityResolver {
	return func() nebridge.IdentityResolver { return nil }
}
