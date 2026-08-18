// Package drift models "normal" egress for a machine and classifies each
// connection as known (silent) or drift (new/unexpected).
//
// This package is observe-only: it never allows or denies traffic. It reads
// decision-log history and the catalog, then returns classifications for
// callers to act on.
package drift

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

// Class is whether a connection matches the established baseline.
type Class string

const (
	ClassKnown Class = "known"
	ClassDrift Class = "drift"
)

// DriftReason explains why a connection was classified as drift. Its zero
// value is valid only when Class == ClassKnown.
type DriftReason string

const (
	ReasonNovelIdentity    DriftReason = "novel_identity"
	ReasonNovelDestination DriftReason = "novel_destination"
	ReasonNovelPairing     DriftReason = "novel_pairing"
)

// Baseline is a per-machine model of normal identity/destination pairs.
type Baseline struct {
	cat          *catalog.Catalog
	identities   map[string]bool
	hosts        map[string]bool
	pairs        map[string]bool
	clouds       *clouds
	builtThrough time.Time
}

// Event is the result of classifying one decisionlog.Entry against a Baseline.
type Event struct {
	Class     Class
	Reason    DriftReason
	Identity  catalog.Identity
	Host      string
	DestIP    string
	FirstSeen time.Time
	Rank      int
	Log       decisionlog.Entry
	// Score is observational joint-distance metadata; decision policy does not
	// branch on it until calibration against real history is complete.
	Score Score
}

const minStableDays = 2

// 5: clouds gained Pair metadata for inspection tooling. Version-4 snapshots
// lack that one-way key metadata and must be rebuilt from the decision log.
const baselineSchemaVersion = 5

const (
	rankNeverHit         = 4
	rankNovelIdentity    = 3
	rankNovelDestination = 2
	rankNovelPairing     = 1
)

type pairStats struct {
	days map[string]bool
	id   string
	host string
}

type baselineSnapshot struct {
	SchemaVersion int                `json:"schema_version"`
	BuiltThrough  string             `json:"built_through"`
	Identities    []string           `json:"identities"`
	Hosts         []string           `json:"hosts"`
	Pairs         []string           `json:"pairs"`
	CloudPoints   map[string][]Point `json:"cloud_points,omitempty"`
	CloudLast     map[string]string  `json:"cloud_last,omitempty"`
	CloudMeta     map[string]Pair    `json:"cloud_meta"`
}

// BuildBaseline folds decision-log history into stable normal traffic. Only
// allow and observe decisions teach the baseline; deny decisions never do.
func BuildBaseline(cat *catalog.Catalog, entries []decisionlog.Entry) *Baseline {
	b := &Baseline{
		cat:        cat,
		identities: map[string]bool{},
		hosts:      map[string]bool{},
		pairs:      map[string]bool{},
	}
	byPair := map[string]*pairStats{}
	var latest time.Time

	for _, e := range entries {
		if !foldsIntoBaseline(e) {
			continue
		}
		id := identityKey(IdentityFromEntry(e))
		host := hostKey(e.Host)
		pair := pairKey(id, host)
		stats, ok := byPair[pair]
		if !ok {
			stats = &pairStats{days: map[string]bool{}, id: id, host: host}
			byPair[pair] = stats
		}
		if ts, err := time.Parse(time.RFC3339, e.Timestamp); err == nil {
			stats.days[ts.UTC().Format("2006-01-02")] = true
			if ts.After(latest) {
				latest = ts
			}
		}
	}

	for pair, stats := range byPair {
		if len(stats.days) < minStableDays {
			continue
		}
		b.identities[stats.id] = true
		b.hosts[stats.host] = true
		b.pairs[pair] = true
	}
	b.builtThrough = latest
	joined := decisionlog.Join(entries)
	concurrency := decisionlog.BuildConcurrencyIndex(joined)
	b.clouds = newClouds()
	for _, joined := range joined {
		if !foldsIntoBaseline(joined.Decision) {
			continue
		}
		identity := IdentityFromEntry(joined.Decision)
		b.clouds.add(pairKey(identityKey(identity), hostKey(joined.Decision.Host)), identity, joined.Decision.Host, joined, concurrency)
	}
	b.clouds.finish()
	return b
}

func foldsIntoBaseline(e decisionlog.Entry) bool {
	return !e.IsFlow() && e.Decision != decisionlog.DecisionDeny
}

// Classify scores one decision-log entry against the baseline. It ignores the
// entry decision because drift asks whether this pair is normal, not whether
// this attempt was allowed.
func (b *Baseline) Classify(e decisionlog.Entry) Event {
	return b.classify(e, 0)
}

// ClassifyLive scores a connection that is still open. concurrency is the
// number of other connections the daemon currently has in flight; it is not
// persisted and complements the concurrency derived from closed log records.
func (b *Baseline) ClassifyLive(e decisionlog.Entry, concurrency int) Event {
	return b.classify(e, concurrency)
}

func (b *Baseline) classify(e decisionlog.Entry, concurrency int) Event {
	id := IdentityFromEntry(e)
	idKey := identityKey(id)
	hKey := hostKey(e.Host)
	pKey := pairKey(idKey, hKey)
	hostKnown := b.hosts[hKey]
	firstSeen, _ := time.Parse(time.RFC3339, e.Timestamp)
	ev := Event{
		Identity:  id,
		Host:      e.Host,
		DestIP:    e.DestIP,
		FirstSeen: firstSeen,
		Log:       e,
	}
	ev.Score = b.ScoreLive(id, e.Host, decisionlog.Joined{Decision: e}, concurrency)

	if b.pairs[pKey] {
		ev.Class = ClassKnown
		return ev
	}
	if b.cat != nil {
		match := b.cat.Lookup(id, e.Host)
		if match.NeverHit {
			ev.Class = ClassDrift
			ev.Reason = ReasonNovelPairing
			ev.Rank = rankNeverHit
			return ev
		}
		if match.Found && match.Authoritative {
			ev.Class = ClassKnown
			return ev
		}
		if b.cat.HasHost(e.Host) {
			hostKnown = true
		}
	}

	ev.Class = ClassDrift
	switch {
	case !b.identities[idKey]:
		ev.Reason = ReasonNovelIdentity
		ev.Rank = rankNovelIdentity
	case !hostKnown:
		ev.Reason = ReasonNovelDestination
		ev.Rank = rankNovelDestination
	default:
		ev.Reason = ReasonNovelPairing
		ev.Rank = rankNovelPairing
	}
	return ev
}

// ScoreLive scores one connection against the selected pair cloud. A live
// ClientHello has no close-time flow metadata, so a known pair receives a
// finite observational score without inventing byte counts.
func (b *Baseline) ScoreLive(id catalog.Identity, host string, joined decisionlog.Joined, concurrency int) Score {
	point, ok := PointFrom(joined, b.LastSeenFor(id, host), concurrency)
	if !ok {
		return Score{}
	}
	cloud, scale := b.CloudFor(id, host)
	return ScorePoint(point, cloud, scale)
}

// Explain renders the score's human-facing attribution without treating an
// empty history as a fabricated comparison.
func (event Event) Explain() string {
	if !event.Score.Scored {
		return "Joint drift score is not available until this connection closes."
	}
	if math.IsInf(event.Score.Distance, 1) || !event.Score.HasNearest {
		return "This pairing has no history on this machine."
	}
	names := make([]string, 0, len(event.Score.Dominant))
	for _, dim := range event.Score.Dominant {
		names = append(names, DimNames[dim])
	}
	if len(names) == 0 {
		return fmt.Sprintf("This connection is typical of the %d comparable ones before it.", event.Score.Neighbours)
	}
	return fmt.Sprintf("Unusual %s compared with the %d most similar of this pair's previous connections.", strings.Join(names, " and "), event.Score.Neighbours)
}

// Analyze classifies a window and returns only drift, highest-signal first.
func Analyze(window []decisionlog.Entry, b *Baseline) []Event {
	var out []Event
	for _, e := range window {
		ev := b.Classify(e)
		if ev.Class == ClassDrift {
			out = append(out, ev)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Rank != out[j].Rank {
			return out[i].Rank > out[j].Rank
		}
		return out[i].FirstSeen.Before(out[j].FirstSeen)
	})
	return out
}

// BuiltThrough is the newest decision-log timestamp folded into this baseline.
func (b *Baseline) BuiltThrough() time.Time {
	return b.builtThrough
}

// IsStale reports whether entries contain traffic newer than this baseline.
func (b *Baseline) IsStale(entries []decisionlog.Entry) bool {
	for _, e := range entries {
		if !foldsIntoBaseline(e) {
			continue
		}
		ts, err := time.Parse(time.RFC3339, e.Timestamp)
		if err == nil && ts.After(b.builtThrough) {
			return true
		}
	}
	return false
}

// Save persists the folded baseline maps as a recompute-on-stale cache.
func (b *Baseline) Save(path string) error {
	snap := baselineSnapshot{
		SchemaVersion: baselineSchemaVersion,
		BuiltThrough:  b.builtThrough.UTC().Format(time.RFC3339),
		Identities:    sortedKeys(b.identities),
		Hosts:         sortedKeys(b.hosts),
		Pairs:         sortedKeys(b.pairs),
		CloudPoints:   b.clouds.points,
		CloudLast:     cloudLastStrings(b.clouds),
		CloudMeta:     b.clouds.meta,
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("drift: marshal baseline: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("drift: mkdir baseline dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("drift: write baseline: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("drift: rename baseline: %w", err)
	}
	return nil
}

// LoadBaseline reads a baseline cache and reattaches cat by reference.
func LoadBaseline(path string, cat *catalog.Catalog) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, fmt.Errorf("drift: read baseline %s: %w", path, err)
	}
	var snap baselineSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("drift: parse baseline: %w", err)
	}
	if snap.SchemaVersion == 2 {
		return nil, os.ErrNotExist
	}
	if snap.SchemaVersion != baselineSchemaVersion {
		return nil, fmt.Errorf("drift: baseline schema version %d unsupported (want %d)", snap.SchemaVersion, baselineSchemaVersion)
	}
	if snap.CloudMeta == nil {
		return nil, fmt.Errorf("drift: baseline missing cloud pair metadata")
	}
	builtThrough, _ := time.Parse(time.RFC3339, snap.BuiltThrough)
	cloud := newClouds()
	cloud.points = snap.CloudPoints
	if cloud.points == nil {
		cloud.points = map[string][]Point{}
	}
	cloud.meta = snap.CloudMeta
	for key, value := range snap.CloudLast {
		if timestamp, err := time.Parse(time.RFC3339, value); err == nil {
			cloud.last[key] = timestamp
		}
	}
	cloud.finish()
	return &Baseline{
		cat:          cat,
		identities:   sliceToSet(snap.Identities),
		hosts:        sliceToSet(snap.Hosts),
		pairs:        sliceToSet(snap.Pairs),
		clouds:       cloud,
		builtThrough: builtThrough,
	}, nil
}

func cloudLastStrings(cloud *clouds) map[string]string {
	if cloud == nil {
		return nil
	}
	last := make(map[string]string, len(cloud.last))
	for key, timestamp := range cloud.last {
		last[key] = timestamp.UTC().Format(time.RFC3339)
	}
	return last
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sliceToSet(s []string) map[string]bool {
	out := make(map[string]bool, len(s))
	for _, k := range s {
		out[k] = true
	}
	return out
}

// IdentityFromEntry is the single identity-key construction used by baseline
// building and calibration. A hash tied to an absolute executable path is
// path-sensitive, so callers must not reconstruct this identity by hand.
func IdentityFromEntry(e decisionlog.Entry) catalog.Identity {
	base := filepath.Base(e.Exe)
	if base == "" || base == "." {
		base = e.Comm
	}
	id := catalog.Identity{ExeBasename: base, ExeSHA256: e.ExeSHA256, TeamID: e.TeamID}
	if id.ExeSHA256 != "" && filepath.IsAbs(e.Exe) {
		id.ExePath = e.Exe
	}
	return id
}

func identityKey(id catalog.Identity) string {
	return id.ExePath + "\x00" + id.ExeSHA256 + "\x00" + id.TeamID + "\x00" + id.ExeBasename
}

func hostKey(host string) string {
	return strings.ToLower(host)
}

func pairKey(idKey, hKey string) string {
	return idKey + "\x00" + hKey
}
