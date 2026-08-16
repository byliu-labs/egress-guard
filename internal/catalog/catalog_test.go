package catalog

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const validEntryTOML = `
[[entry]]
schema_version = 1
layer = "baseline"
confidence = "high"
evidence = "codesign -dvv verified; TeamID EQHXZ8M8AV is Google's Apple Developer ID, matches published Chrome release notes."
explanation = "Chrome checks for updates and syncs bookmarks with Google's own infrastructure."
never = ["evil.example.com"]

[entry.identity]
bundle_id = "com.google.Chrome"
team_id   = "EQHXZ8M8AV"

[[entry.expected_destinations]]
host = "update.googleapis.com"
why  = "Chrome auto-update channel"

[[entry.expected_destinations]]
host = "clients2.google.com"
why  = "Chrome component + extension updates"
`

func TestLoad_AcceptsWellFormedEntry(t *testing.T) {
	c, err := Load([]byte(validEntryTOML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(c.entries))
	}
	e := c.entries[0]
	if e.Identity.BundleID != "com.google.Chrome" || e.Confidence != ConfidenceHigh {
		t.Errorf("unexpected entry: %+v", e)
	}
	if len(e.ExpectedDestinations) != 2 {
		t.Errorf("got %d expected_destinations, want 2", len(e.ExpectedDestinations))
	}
}

func TestLoad_RejectsMissingEvidence(t *testing.T) {
	toml := `
[[entry]]
schema_version = 1
layer = "baseline"
confidence = "high"
explanation = "no evidence attached"

[entry.identity]
bundle_id = "com.example.App"
team_id   = "TEAM123"
`
	if _, err := Load([]byte(toml)); err == nil {
		t.Errorf("expected error for missing evidence")
	}
}

func TestLoad_RejectsConfidenceLow(t *testing.T) {
	toml := `
[[entry]]
schema_version = 1
layer = "baseline"
confidence = "low"
evidence = "some evidence"
explanation = "some explanation"

[entry.identity]
bundle_id = "com.example.App"
team_id   = "TEAM123"
`
	if _, err := Load([]byte(toml)); err == nil {
		t.Errorf("expected error for confidence:low")
	}
}

func TestLoad_RejectsConfidenceEmpty(t *testing.T) {
	toml := `
[[entry]]
schema_version = 1
layer = "baseline"
evidence = "some evidence"
explanation = "some explanation"

[entry.identity]
bundle_id = "com.example.App"
`
	if _, err := Load([]byte(toml)); err == nil {
		t.Errorf("expected error for empty confidence")
	}
}

func TestLoad_RejectsEmptyIdentity(t *testing.T) {
	toml := `
[[entry]]
schema_version = 1
layer = "baseline"
confidence = "medium"
evidence = "some evidence"
explanation = "some explanation"
`
	if _, err := Load([]byte(toml)); err == nil {
		t.Errorf("expected error for empty identity (no bundle_id or exe_basename)")
	}
}

func TestLoad_RejectsHighConfidenceWithoutSignatureAnchor(t *testing.T) {
	toml := `
[[entry]]
schema_version = 1
layer = "baseline"
confidence = "high"
evidence = "some evidence"
explanation = "some explanation"

[entry.identity]
exe_basename = "mytool"
`
	if _, err := Load([]byte(toml)); err == nil {
		t.Errorf("expected error: exe_basename-only identity cannot carry confidence:high")
	}
}

func TestLoad_AcceptsMediumConfidenceNameOnlyIdentity(t *testing.T) {
	toml := `
[[entry]]
schema_version = 1
layer = "baseline"
confidence = "medium"
evidence = "some evidence"
explanation = "some explanation"

[entry.identity]
exe_basename = "mytool"
`
	if _, err := Load([]byte(toml)); err != nil {
		t.Errorf("name-only identity at confidence:medium should be accepted, got %v", err)
	}
}

func TestLoad_RejectsInvalidLayer(t *testing.T) {
	toml := `
[[entry]]
schema_version = 1
layer = "enterprise"
confidence = "medium"
evidence = "some evidence"
explanation = "some explanation"

[entry.identity]
exe_basename = "mytool"
`
	if _, err := Load([]byte(toml)); err == nil {
		t.Errorf("expected error for invalid layer")
	}
}

func TestLoad_RejectsUnsupportedSchemaVersion(t *testing.T) {
	toml := `
[[entry]]
schema_version = 2
layer = "baseline"
confidence = "medium"
evidence = "some evidence"
explanation = "some explanation"

[entry.identity]
exe_basename = "mytool"
`
	if _, err := Load([]byte(toml)); err == nil {
		t.Errorf("expected error for unsupported schema_version")
	}
}

func TestLoad_RejectsMissingExplanation(t *testing.T) {
	toml := `
[[entry]]
schema_version = 1
layer = "baseline"
confidence = "medium"
evidence = "some evidence"

[entry.identity]
exe_basename = "mytool"
`
	if _, err := Load([]byte(toml)); err == nil {
		t.Errorf("expected error for missing explanation")
	}
}

func TestLoadFile_AbsentReturnsErrNotExist(t *testing.T) {
	_, err := LoadFile("/nonexistent/path/catalog.toml")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("want os.ErrNotExist, got %v", err)
	}
}

func TestLoadFile_ReadsValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.toml")
	if err := os.WriteFile(path, []byte(validEntryTOML), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	c, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(c.entries) != 1 {
		t.Errorf("got %d entries, want 1", len(c.entries))
	}
}

func TestCatalog_Merge(t *testing.T) {
	base, err := Load([]byte(validEntryTOML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	userTOML := `
[[entry]]
schema_version = 1
layer = "user"
confidence = "medium"
evidence = "user ratified this on 2026-07-06 after a drift prompt"
explanation = "MyTool talks to its own backend"

[entry.identity]
exe_basename = "mytool"
`
	user, err := Load([]byte(userTOML))
	if err != nil {
		t.Fatalf("Load(user): %v", err)
	}
	base.Merge(user)
	if len(base.entries) != 2 {
		t.Fatalf("got %d entries after merge, want 2", len(base.entries))
	}
}

func TestCatalog_Lookup_NoMatch(t *testing.T) {
	c, err := Load([]byte(validEntryTOML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	res := c.Lookup(Identity{BundleID: "com.unknown.App"}, "example.com")
	if res.Found {
		t.Errorf("unexpected match for unknown identity: %+v", res)
	}
}

func TestCatalog_Lookup_ExpectedDestination(t *testing.T) {
	c, err := Load([]byte(validEntryTOML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	res := c.Lookup(Identity{BundleID: "com.google.Chrome", TeamID: "EQHXZ8M8AV"}, "update.googleapis.com")
	if !res.Found || res.NeverHit {
		t.Errorf("got %+v, want Found=true NeverHit=false", res)
	}
}

func TestCatalog_Lookup_NeverHit(t *testing.T) {
	c, err := Load([]byte(validEntryTOML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	res := c.Lookup(Identity{BundleID: "com.google.Chrome", TeamID: "EQHXZ8M8AV"}, "evil.example.com")
	if !res.Found || !res.NeverHit {
		t.Errorf("got %+v, want Found=true NeverHit=true", res)
	}
}

func TestCatalog_Lookup_NeverDominatesAcrossMergedLayers(t *testing.T) {
	baseTOML := `
[[entry]]
schema_version = 1
layer = "baseline"
confidence = "high"
evidence = "baseline catalog says this is normal"
explanation = "Chrome expected destination"

[entry.identity]
bundle_id = "com.google.Chrome"
team_id   = "EQHXZ8M8AV"

[[entry.expected_destinations]]
host = "update.googleapis.com"
`
	userTOML := `
[[entry]]
schema_version = 1
layer = "user"
confidence = "high"
evidence = "user explicitly marked this host never on 2026-07-06"
explanation = "Local policy forbids this destination"
never = ["update.googleapis.com"]

[entry.identity]
bundle_id = "com.google.Chrome"
team_id   = "EQHXZ8M8AV"
`
	base, err := Load([]byte(baseTOML))
	if err != nil {
		t.Fatalf("Load(base): %v", err)
	}
	user, err := Load([]byte(userTOML))
	if err != nil {
		t.Fatalf("Load(user): %v", err)
	}
	base.Merge(user)

	res := base.Lookup(Identity{BundleID: "com.google.Chrome", TeamID: "EQHXZ8M8AV"}, "update.googleapis.com")
	if !res.Found || !res.NeverHit {
		t.Fatalf("got %+v, want never hit to dominate earlier expected destination", res)
	}
	if res.Entry.Layer != "user" {
		t.Errorf("Entry.Layer = %q, want user", res.Entry.Layer)
	}
}

func TestCatalog_Lookup_IdentityKnownDestinationUnknown(t *testing.T) {
	c, err := Load([]byte(validEntryTOML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	res := c.Lookup(Identity{BundleID: "com.google.Chrome", TeamID: "EQHXZ8M8AV"}, "totally-unrelated.example.com")
	if res.Found {
		t.Errorf("destination absent from both expected_destinations and never must not be Found; got %+v", res)
	}
}

func TestCatalog_HasHost(t *testing.T) {
	c, err := Load([]byte(validEntryTOML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.HasHost("UPDATE.GOOGLEAPIS.COM.") {
		t.Errorf("HasHost should match expected destinations with catalog host normalization")
	}
	if !c.HasHost("evil.example.com") {
		t.Errorf("HasHost should match never destinations too")
	}
	if c.HasHost("unknown.example.com") {
		t.Errorf("HasHost returned true for an unknown host")
	}
}

func TestCatalog_Lookup_NameOnlyEntryExplainsButDoesNotDecide(t *testing.T) {
	toml := `
[[entry]]
schema_version = 1
layer = "baseline"
confidence = "medium"
evidence = "observed consistently across dev machines"
explanation = "mytool phones home to its own API"

[entry.identity]
exe_basename = "mytool"

[[entry.expected_destinations]]
host = "api.mytool.example"
`
	c, err := Load([]byte(toml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	res := c.Lookup(Identity{ExeBasename: "mytool"}, "api.mytool.example")
	if !res.Found {
		t.Errorf("name-only identity should explain the prompt: %+v", res)
	}
	if res.Authoritative {
		t.Errorf("name-only baseline identity must not decide silently: %+v", res)
	}
}

func TestCatalog_Lookup_NameOnlyNeverHit(t *testing.T) {
	toml := `
[[entry]]
schema_version = 1
layer = "baseline"
confidence = "medium"
evidence = "observed consistently across dev machines"
explanation = "mytool must never reach this host"
never = ["blocked.mytool.example"]

[entry.identity]
exe_basename = "mytool"
`
	c, err := Load([]byte(toml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	res := c.Lookup(Identity{ExeBasename: "mytool"}, "blocked.mytool.example")
	if !res.Found || !res.NeverHit {
		t.Errorf("name-only never rule should be visible to lookup: %+v", res)
	}
	if res.Authoritative {
		t.Errorf("name-only baseline never rule must not be marked authoritative: %+v", res)
	}
}

func TestCatalog_Lookup_AuthoritativeExpectedDestinationWinsOverEarlierPromptContext(t *testing.T) {
	baseTOML := `
[[entry]]
schema_version = 1
layer = "baseline"
confidence = "medium"
evidence = "baseline explains a common tool"
explanation = "mytool talks to its API"

[entry.identity]
exe_basename = "mytool"

[[entry.expected_destinations]]
host = "api.mytool.example"
`
	userTOML := `
[[entry]]
schema_version = 1
layer = "user"
confidence = "medium"
evidence = "user ratified after a drift prompt"
explanation = "mytool talks to its API"

[entry.identity]
exe_basename = "mytool"

[[entry.expected_destinations]]
host = "api.mytool.example"
`
	base, err := Load([]byte(baseTOML))
	if err != nil {
		t.Fatalf("Load(base): %v", err)
	}
	user, err := Load([]byte(userTOML))
	if err != nil {
		t.Fatalf("Load(user): %v", err)
	}
	base.Merge(user)

	res := base.Lookup(Identity{ExeBasename: "mytool"}, "api.mytool.example")
	if !res.Found || !res.Authoritative {
		t.Fatalf("user ratification should make later matching lookups authoritative: %+v", res)
	}
	if res.Entry.Layer != "user" {
		t.Fatalf("Entry.Layer = %q, want user", res.Entry.Layer)
	}
}

func TestCatalog_Lookup_ExeSHA256PinsIdentity(t *testing.T) {
	toml := `
[[entry]]
schema_version = 1
layer = "baseline"
confidence = "medium"
evidence = "operator pinned this exact tool binary by sha256"
explanation = "mytool phones home to its own API"

[entry.identity]
exe_basename = "mytool"
exe_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[entry.expected_destinations]]
host = "api.mytool.example"
`
	c, err := Load([]byte(toml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := c.Lookup(Identity{ExeBasename: "mytool", ExeSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, "api.mytool.example"); got.Found {
		t.Fatalf("wrong binary hash matched catalog entry: %+v", got)
	}
	if got := c.Lookup(Identity{ExeBasename: "mytool", ExeSHA256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, "api.mytool.example"); !got.Found || !got.Authoritative {
		t.Fatalf("matching binary hash did not match catalog entry: %+v", got)
	}
}

func TestCatalog_Add_ValidatesAndAppends(t *testing.T) {
	c := &Catalog{}
	e := Entry{
		SchemaVersion: 1,
		Layer:         "user",
		Confidence:    ConfidenceMedium,
		Evidence:      "user ratified after a drift prompt",
		Explanation:   "MyTool talks to its own backend",
		Identity:      Identity{ExeBasename: "mytool"},
	}
	if err := c.Add(e); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if len(c.entries) != 1 {
		t.Errorf("got %d entries, want 1", len(c.entries))
	}
}

func TestCatalog_Add_RejectsInvalidEntry(t *testing.T) {
	c := &Catalog{}
	e := Entry{SchemaVersion: 1, Layer: "user", Confidence: "low"}
	if err := c.Add(e); err == nil {
		t.Errorf("expected error for confidence:low")
	}
	if len(c.entries) != 0 {
		t.Errorf("invalid entry must not be appended, got %d entries", len(c.entries))
	}
}

func TestCatalog_MarshalRoundTrip(t *testing.T) {
	c := &Catalog{}
	e := Entry{
		SchemaVersion: 1,
		Layer:         "user",
		Confidence:    ConfidenceMedium,
		Evidence:      "user ratified after a drift prompt on 2026-07-06",
		Explanation:   "MyTool talks to its own backend",
		Identity:      Identity{ExeBasename: "mytool", TeamID: "USERTEAM"},
		ExpectedDestinations: []Destination{
			{Host: "api.mytool.example", Why: "primary backend"},
		},
		Never: []string{"evil.example.com"},
	}
	if err := c.Add(e); err != nil {
		t.Fatalf("Add: %v", err)
	}

	b, err := c.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	reloaded, err := Load(b)
	if err != nil {
		t.Fatalf("Load(marshaled): %v\n---\n%s", err, b)
	}
	if len(reloaded.entries) != 1 {
		t.Fatalf("got %d entries after round-trip, want 1", len(reloaded.entries))
	}
	got := reloaded.entries[0]
	if got.Identity.ExeBasename != "mytool" || got.Identity.TeamID != "USERTEAM" {
		t.Errorf("identity mismatch after round-trip: %+v", got.Identity)
	}
	if got.Confidence != ConfidenceMedium || got.Evidence != e.Evidence || got.Explanation != e.Explanation {
		t.Errorf("scalar field mismatch after round-trip: %+v", got)
	}
	if len(got.ExpectedDestinations) != 1 || got.ExpectedDestinations[0].Host != "api.mytool.example" {
		t.Errorf("expected_destinations mismatch after round-trip: %+v", got.ExpectedDestinations)
	}
	if len(got.Never) != 1 || got.Never[0] != "evil.example.com" {
		t.Errorf("never mismatch after round-trip: %+v", got.Never)
	}
}
