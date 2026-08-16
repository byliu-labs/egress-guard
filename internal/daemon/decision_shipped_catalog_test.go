package daemon

import (
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

func TestShippedCatalog_BasenameOnlyEntryPromptsWithExplanationButNeverAllows(t *testing.T) {
	cat, err := catalog.LoadFile(filepath.Join("..", "..", "catalog-baseline.toml"))
	if err != nil {
		t.Fatalf("LoadFile(catalog-baseline.toml): %v", err)
	}
	if cat.EntryCount() != 10 {
		t.Fatalf("shipped baseline entry count = %d, want 10", cat.EntryCount())
	}

	cases := []struct {
		exe  string
		host string
	}{
		{"npm", "registry.npmjs.org"},
		{"git", "github.com"},
		{"brew", "formulae.brew.sh"},
		{"pip", "pypi.org"},
	}
	for _, tc := range cases {
		t.Run(tc.exe, func(t *testing.T) {
			dec := &capturingDecider{}
			d := newDaemonForBranchWithCatalog(t, dec, cat)
			pi := procid.ProcInfo{PID: 30, Exe: "/usr/bin/" + tc.exe, Comm: tc.exe}

			outcome, _ := d.decideBranch(tc.host, nil, pi, signature.SignedIdentity{})
			if outcome == outcomeAllow {
				t.Fatal("basename-only baseline entry produced a silent allow")
			}
			if !dec.called {
				t.Fatal("prompt was not shown for basename-only baseline entry")
			}
			if !dec.got.CatalogMatch.Found {
				t.Fatal("prompt did not receive the baseline explanation")
			}
			if dec.got.CatalogMatch.Authoritative {
				t.Fatal("basename-only baseline entry must not be authoritative")
			}
		})
	}
}
