package daemon

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/explain"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/prompt"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

// fakeExplainer is a test double for explain.Explainer.
type fakeExplainer struct {
	exp   explain.Explanation
	err   error
	block bool // if set, blocks until ctx is done (to exercise the timeout)
}

func (f *fakeExplainer) Explain(ctx context.Context, id catalog.Identity, host string) (explain.Explanation, error) {
	if f.block {
		<-ctx.Done()
		return explain.Explanation{}, ctx.Err()
	}
	return f.exp, f.err
}

// capturingDecider records the Request it received and returns a fixed verdict.
type capturingDecider struct {
	got    prompt.Request
	called bool
}

func (c *capturingDecider) Decide(ctx context.Context, req prompt.Request) prompt.Decision {
	c.got = req
	c.called = true
	return prompt.Deny // verdict is irrelevant to these tests
}

// unknownDaemon builds a daemon whose allowlist returns Unknown for any host,
// so decideBranch always reaches the prompt branch. No catalog → no match.
func unknownDaemon(t *testing.T, ex explain.Explainer, dec prompt.Decider) *Daemon {
	t.Helper()
	return &Daemon{opts: Options{
		Allow:     allowlist.New(allowlist.Config{}), // empty → Decide == Unknown
		Prompt:    dec,
		Explainer: ex,
	}}
}

func drive(t *testing.T, d *Daemon) {
	t.Helper()
	d.decideBranch("unknown.example.com", net.IPv4(93, 184, 216, 34),
		procid.ProcInfo{Exe: "/usr/bin/curl", PID: 1},
		signature.SignedIdentity{})
}

// TestOptions_ExplainerFieldExists asserts the daemon accepts an Explainer and
// Logger.
func TestOptions_ExplainerFieldExists(t *testing.T) {
	_ = Options{
		Explainer: &fakeExplainer{},
		Logger:    nil,
	}
}

func TestDecideBranch_PopulatesOpinionFromExplainer(t *testing.T) {
	dec := &capturingDecider{}
	ex := &fakeExplainer{exp: explain.New("curl talks to a CDN", catalog.ConfidenceMedium, "reachability probe", nil)}
	d := unknownDaemon(t, ex, dec)

	drive(t, d)

	if !dec.called {
		t.Fatal("prompt decider was not called")
	}
	if dec.got.Opinion == nil {
		t.Fatal("expected req.Opinion populated from explainer, got nil")
	}
	if dec.got.Opinion.Text != "curl talks to a CDN" {
		t.Fatalf("opinion text = %q, want the explainer's text", dec.got.Opinion.Text)
	}
	if !dec.got.Opinion.ModelOpinion {
		t.Fatal("opinion must be flagged ModelOpinion (never a catalog fact)")
	}
}

func TestDecideBranch_ExplainerErrorLeavesOpinionNil(t *testing.T) {
	dec := &capturingDecider{}
	ex := &fakeExplainer{err: errForTest("endpoint down")}
	d := unknownDaemon(t, ex, dec)

	drive(t, d)

	if !dec.called {
		t.Fatal("prompt must still be shown when the explainer errors")
	}
	if dec.got.Opinion != nil {
		t.Fatal("explainer error must leave Opinion nil (fail open)")
	}
}

func TestDecideBranch_SlowExplainerIsBoundedAndFailsOpen(t *testing.T) {
	old := explainTimeout
	explainTimeout = 20 * time.Millisecond
	defer func() { explainTimeout = old }()

	dec := &capturingDecider{}
	ex := &fakeExplainer{block: true} // blocks until ctx (our 20ms bound) fires
	d := unknownDaemon(t, ex, dec)

	start := time.Now()
	drive(t, d)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("explainer call not bounded: took %v", elapsed)
	}
	if !dec.called {
		t.Fatal("prompt must still be shown after the explainer times out")
	}
	if dec.got.Opinion != nil {
		t.Fatal("timed-out explainer must leave Opinion nil (fail open)")
	}
}

func TestDecideBranch_NilExplainerLeavesOpinionNil(t *testing.T) {
	dec := &capturingDecider{}
	d := unknownDaemon(t, nil, dec) // no explainer configured

	drive(t, d)

	if !dec.called {
		t.Fatal("prompt decider was not called")
	}
	if dec.got.Opinion != nil {
		t.Fatal("nil explainer must leave Opinion nil (pre-wiring behavior)")
	}
}

type errForTest string

func (e errForTest) Error() string { return string(e) }

// spyExplainer records whether Explain was called.
type spyExplainer struct{ called bool }

func (s *spyExplainer) Explain(ctx context.Context, id catalog.Identity, host string) (explain.Explanation, error) {
	s.called = true
	return explain.Explanation{}, nil
}

// TestDecideBranch_ExplainerNotCalledOnFastPaths hardens the "cold-path only,
// never admission-path" contract against refactors: the explainer must run ONLY
// in the Unknown→prompt branch, never on the allowlist allow/deny fast paths nor
// on a catalog never-hit / catalog-fact resolution.
func TestDecideBranch_ExplainerNotCalledOnFastPaths(t *testing.T) {
	pi := procid.ProcInfo{PID: 10, Exe: "/usr/bin/app", Comm: "app"}
	sig := signature.SignedIdentity{Valid: true, TeamID: "TEAMX"}

	neverCat := &catalog.Catalog{}
	if err := neverCat.Add(catalog.Entry{
		SchemaVersion: catalog.CurrentSchemaVersion,
		Identity:      catalog.Identity{ExeBasename: "app", TeamID: "TEAMX"},
		Never:         []string{"bad.example"},
		Explanation:   "app must never reach bad.example",
		Evidence:      "test fixture",
		Confidence:    catalog.ConfidenceHigh,
		Layer:         "user",
	}); err != nil {
		t.Fatalf("neverCat.Add: %v", err)
	}
	factCat := &catalog.Catalog{}
	if err := factCat.Add(catalog.Entry{
		SchemaVersion:        catalog.CurrentSchemaVersion,
		Identity:             catalog.Identity{ExeBasename: "app", TeamID: "TEAMX"},
		ExpectedDestinations: []catalog.Destination{{Host: "good.example", Why: "test fixture"}},
		Explanation:          "app may reach good.example",
		Evidence:             "test fixture",
		Confidence:           catalog.ConfidenceHigh,
		Layer:                "user",
	}); err != nil {
		t.Fatalf("factCat.Add: %v", err)
	}

	cases := []struct {
		name  string
		allow *allowlist.Allowlist
		cat   *catalog.Catalog
		host  string
	}{
		{"allowlisted", allowlist.New(allowlist.Config{User: allowlist.Layer{Allow: []string{"allow.example"}}}), nil, "allow.example"},
		{"denylisted", allowlist.New(allowlist.Config{User: allowlist.Layer{Deny: []string{"deny.example"}}}), nil, "deny.example"},
		{"catalog_never_hit", allowlist.New(allowlist.Config{}), neverCat, "bad.example"},
		{"catalog_fact", allowlist.New(allowlist.Config{}), factCat, "good.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spy := &spyExplainer{}
			d := &Daemon{opts: Options{Allow: tc.allow, Catalog: tc.cat, Prompt: &capturingDecider{}, Explainer: spy}}
			d.decideBranch(tc.host, net.IPv4(1, 2, 3, 4), pi, sig)
			if spy.called {
				t.Fatalf("%s: explainer must not run on the fast path (it is prompt-branch only)", tc.name)
			}
		})
	}
}
