package drift

import (
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

func TestClassAndReasonValues(t *testing.T) {
	if ClassKnown != "known" {
		t.Errorf("ClassKnown = %q, want %q", ClassKnown, "known")
	}
	if ClassDrift != "drift" {
		t.Errorf("ClassDrift = %q, want %q", ClassDrift, "drift")
	}
	if ReasonNovelIdentity != "novel_identity" {
		t.Errorf("ReasonNovelIdentity = %q, want %q", ReasonNovelIdentity, "novel_identity")
	}
	if ReasonNovelDestination != "novel_destination" {
		t.Errorf("ReasonNovelDestination = %q, want %q", ReasonNovelDestination, "novel_destination")
	}
	if ReasonNovelPairing != "novel_pairing" {
		t.Errorf("ReasonNovelPairing = %q, want %q", ReasonNovelPairing, "novel_pairing")
	}
}

func TestIdentityFromEntry(t *testing.T) {
	tests := []struct {
		name string
		e    decisionlog.Entry
		want catalog.Identity
	}{
		{
			name: "uses basename of full exe path",
			e:    decisionlog.Entry{Exe: "/Applications/Slack.app/Contents/MacOS/Slack", ExeSHA256: "abc123", TeamID: "TEAMSLACK"},
			want: catalog.Identity{ExeBasename: "Slack", ExeSHA256: "abc123", TeamID: "TEAMSLACK"},
		},
		{
			name: "falls back to Comm when Exe is empty",
			e:    decisionlog.Entry{Exe: "", Comm: "curl"},
			want: catalog.Identity{ExeBasename: "curl"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := identityFromEntry(tt.e)
			if got != tt.want {
				t.Errorf("identityFromEntry(%+v) = %+v, want %+v", tt.e, got, tt.want)
			}
		})
	}
}

func TestHostKeyNormalizesCase(t *testing.T) {
	if hostKey("Slack.Com") != hostKey("slack.com") {
		t.Errorf("hostKey should be case-insensitive: %q != %q", hostKey("Slack.Com"), hostKey("slack.com"))
	}
}

func TestPairKeyDistinguishesIdentityAndHost(t *testing.T) {
	idA := identityKey(catalog.Identity{ExeBasename: "Slack", TeamID: "TEAMSLACK"})
	idB := identityKey(catalog.Identity{ExeBasename: "Chrome", TeamID: "TEAMCHROME"})
	pAB := pairKey(idA, hostKey("slack.com"))
	pBB := pairKey(idB, hostKey("slack.com"))
	if pAB == pBB {
		t.Errorf("pairKey collided for different identities on the same host: %q", pAB)
	}
}

func TestBuildBaselineRequiresMultipleDistinctDays(t *testing.T) {
	entryAt := func(day int, decision decisionlog.Decision) decisionlog.Entry {
		ts := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC).AddDate(0, 0, day)
		return decisionlog.Entry{
			Timestamp: ts.Format(time.RFC3339),
			Decision:  decision,
			Exe:       "/usr/bin/backupd",
			TeamID:    "TEAMAPPLE",
			Host:      "backup.example.com",
		}
	}

	t.Run("same-day burst does not become baseline", func(t *testing.T) {
		entries := []decisionlog.Entry{
			entryAt(0, decisionlog.DecisionAllow),
			entryAt(0, decisionlog.DecisionAllow),
			entryAt(0, decisionlog.DecisionAllow),
		}
		b := BuildBaseline(nil, entries)
		id := identityKey(catalog.Identity{ExeBasename: "backupd", TeamID: "TEAMAPPLE"})
		key := pairKey(id, hostKey("backup.example.com"))
		if b.pairs[key] {
			t.Errorf("a single-day burst should not qualify as a stable baseline pair")
		}
	})

	t.Run("two distinct days becomes baseline", func(t *testing.T) {
		entries := []decisionlog.Entry{
			entryAt(0, decisionlog.DecisionAllow),
			entryAt(1, decisionlog.DecisionAllow),
		}
		b := BuildBaseline(nil, entries)
		id := identityKey(catalog.Identity{ExeBasename: "backupd", TeamID: "TEAMAPPLE"})
		hKey := hostKey("backup.example.com")
		key := pairKey(id, hKey)
		if !b.pairs[key] {
			t.Errorf("two distinct days should qualify as a stable baseline pair")
		}
		if !b.identities[id] {
			t.Errorf("identity should be marked known once its pair is stable")
		}
		if !b.hosts[hKey] {
			t.Errorf("host should be marked known once its pair is stable")
		}
	})

	t.Run("denied entries never contribute even across many days", func(t *testing.T) {
		entries := []decisionlog.Entry{
			entryAt(0, decisionlog.DecisionDeny),
			entryAt(1, decisionlog.DecisionDeny),
			entryAt(2, decisionlog.DecisionDeny),
		}
		b := BuildBaseline(nil, entries)
		id := identityKey(catalog.Identity{ExeBasename: "backupd", TeamID: "TEAMAPPLE"})
		key := pairKey(id, hostKey("backup.example.com"))
		if b.pairs[key] {
			t.Errorf("denied traffic must never become a baseline pair")
		}
	})

	t.Run("observe decisions contribute same as allow", func(t *testing.T) {
		entries := []decisionlog.Entry{
			entryAt(0, decisionlog.DecisionObserve),
			entryAt(1, decisionlog.DecisionObserve),
		}
		b := BuildBaseline(nil, entries)
		id := identityKey(catalog.Identity{ExeBasename: "backupd", TeamID: "TEAMAPPLE"})
		key := pairKey(id, hostKey("backup.example.com"))
		if !b.pairs[key] {
			t.Errorf("observe-mode traffic recurring across days should still become a stable baseline pair")
		}
	})
}

func seedCatalog(t *testing.T, entries ...catalog.Entry) *catalog.Catalog {
	t.Helper()
	cat, err := catalog.Load([]byte(""))
	if err != nil {
		t.Fatalf("catalog.Load(empty): %v", err)
	}
	for _, e := range entries {
		if err := cat.Add(e); err != nil {
			t.Fatalf("cat.Add(%+v): %v", e, err)
		}
	}
	return cat
}

func TestClassify(t *testing.T) {
	baseTime := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	cat := seedCatalog(t,
		catalog.Entry{
			SchemaVersion:        catalog.CurrentSchemaVersion,
			Identity:             catalog.Identity{ExeBasename: "Chrome", TeamID: "TEAMCHROME"},
			ExpectedDestinations: []catalog.Destination{{Host: "google.com", Why: "sync"}},
			Explanation:          "Chrome talks to Google services",
			Evidence:             "vendor docs",
			Confidence:           catalog.ConfidenceHigh,
			Layer:                "baseline",
		},
		catalog.Entry{
			SchemaVersion:        catalog.CurrentSchemaVersion,
			Identity:             catalog.Identity{ExeBasename: "backupd", TeamID: "TEAMAPPLE"},
			ExpectedDestinations: []catalog.Destination{{Host: "backup.example.com", Why: "time machine"}},
			Never:                []string{"evil.example.com"},
			Explanation:          "backupd should only ever reach Apple backup infra",
			Evidence:             "vendor docs",
			Confidence:           catalog.ConfidenceHigh,
			Layer:                "baseline",
		},
	)
	learned := []decisionlog.Entry{
		{Timestamp: baseTime.Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/Applications/Slack.app/MacOS/Slack", TeamID: "TEAMSLACK", Host: "slack.com"},
		{Timestamp: baseTime.AddDate(0, 0, 1).Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/Applications/Slack.app/MacOS/Slack", TeamID: "TEAMSLACK", Host: "slack.com"},
	}
	b := BuildBaseline(cat, learned)

	tests := []struct {
		name       string
		e          decisionlog.Entry
		wantClass  Class
		wantReason DriftReason
	}{
		{
			name:      "self-learned stable pair is known",
			e:         decisionlog.Entry{Timestamp: baseTime.AddDate(0, 0, 5).Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/Applications/Slack.app/MacOS/Slack", TeamID: "TEAMSLACK", Host: "slack.com"},
			wantClass: ClassKnown,
		},
		{
			name:      "denied re-attempt of an already-known pair is still known",
			e:         decisionlog.Entry{Timestamp: baseTime.AddDate(0, 0, 5).Format(time.RFC3339), Decision: decisionlog.DecisionDeny, Exe: "/Applications/Slack.app/MacOS/Slack", TeamID: "TEAMSLACK", Host: "slack.com"},
			wantClass: ClassKnown,
		},
		{
			name:      "catalog-known pair is known",
			e:         decisionlog.Entry{Timestamp: baseTime.Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/Applications/Google Chrome.app/MacOS/Chrome", TeamID: "TEAMCHROME", Host: "google.com"},
			wantClass: ClassKnown,
		},
		{
			name:       "catalog Never hit is drift regardless of catalog match",
			e:          decisionlog.Entry{Timestamp: baseTime.Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/usr/libexec/backupd", TeamID: "TEAMAPPLE", Host: "evil.example.com"},
			wantClass:  ClassDrift,
			wantReason: ReasonNovelPairing,
		},
		{
			name:       "brand new identity is novel_identity",
			e:          decisionlog.Entry{Timestamp: baseTime.Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/tmp/mystery-binary", Host: "slack.com"},
			wantClass:  ClassDrift,
			wantReason: ReasonNovelIdentity,
		},
		{
			name:       "known identity to brand new host is novel_destination",
			e:          decisionlog.Entry{Timestamp: baseTime.Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/Applications/Slack.app/MacOS/Slack", TeamID: "TEAMSLACK", Host: "never-seen-before.example.com"},
			wantClass:  ClassDrift,
			wantReason: ReasonNovelDestination,
		},
		{
			name:       "known identity and known host but new pairing between them is novel_pairing",
			e:          decisionlog.Entry{Timestamp: baseTime.Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/Applications/Slack.app/MacOS/Slack", TeamID: "TEAMSLACK", Host: "google.com"},
			wantClass:  ClassDrift,
			wantReason: ReasonNovelPairing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := b.Classify(tt.e)
			if ev.Class != tt.wantClass {
				t.Errorf("Class = %q, want %q", ev.Class, tt.wantClass)
			}
			if ev.Class == ClassDrift && ev.Reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q", ev.Reason, tt.wantReason)
			}
			if ev.Class == ClassKnown && ev.Reason != "" {
				t.Errorf("Reason must be zero value for known events, got %q", ev.Reason)
			}
		})
	}
}
