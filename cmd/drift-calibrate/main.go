// Command drift-calibrate reports the distribution of joint drift scores in a
// decision log. It is read-only: calibration chooses a future policy threshold.
package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/drift"
)

func main() {
	logPath := flag.String("log", "", "path to decisions.log")
	train := flag.Float64("train", 0.7, "fraction of history used to build the baseline")
	flag.Parse()
	if *logPath == "" || *train <= 0 || *train >= 1 {
		fmt.Fprintln(os.Stderr, "usage: drift-calibrate -log <path> [-train 0.7]")
		os.Exit(2)
	}
	entries, err := decisionlog.Read(*logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", *logPath, err)
		os.Exit(1)
	}
	scores, infinite, unscorable := scoresForEntries(entries, *train)
	sort.Float64s(scores)
	fmt.Printf("connections scored: %d (+%d with no history, +%d unscorable)\n",
		len(scores), infinite, unscorable)
	for _, q := range []float64{0.5, 0.9, 0.95, 0.99, 0.999} {
		fmt.Printf("  p%-5.1f  %.3f\n", q*100, quantile(scores, q))
	}
	fmt.Println()
	fmt.Println("Choose promptDistance so the prompt rate is tolerable:")
	for _, q := range []float64{0.99, 0.995, 0.999} {
		fmt.Printf("  threshold %.3f -> %.2f%% of connections prompt\n", quantile(scores, q), (1-q)*100)
	}
}

// scoresForEntries returns the measured distances, the count of connections
// whose pair had no history, and the count that could not be scored at all.
// The three are kept apart deliberately: an unscorable connection is a
// non-measurement, and folding it into the sample as distance 0 would report a
// median joint distance of zero and understate the prompt rate of any
// threshold chosen from these quantiles.
func scoresForEntries(entries []decisionlog.Entry, train float64) ([]float64, int, int) {
	joined := decisionlog.Join(entries)
	cut := int(float64(len(joined)) * train)
	var training []decisionlog.Entry
	for _, item := range joined[:cut] {
		training = append(training, item.Decision)
		if item.HasFlow {
			training = append(training, item.Flow)
		}
	}
	baseline := drift.BuildBaseline(&catalog.Catalog{}, training)
	// The clouds carry a concurrency derived from the log, so the connections
	// scored against them must carry one too. Passing zero here would score
	// every connection that had company as if it had none, offsetting the whole
	// sample from the geometry the daemon will actually use.
	index := decisionlog.BuildConcurrencyIndex(joined)
	var scores []float64
	infinite, unscorable := 0, 0
	// Seed the replay's last-seen state from the training half, so the first
	// held-out connection is measured against the connection that really
	// preceded it rather than against nothing.
	lastSeen := map[string]time.Time{}
	for _, item := range joined[:cut] {
		if at, err := time.Parse(time.RFC3339, item.Decision.Timestamp); err == nil {
			lastSeen[pairKeyOf(item.Decision)] = at
		}
	}
	for _, item := range joined[cut:] {
		identity := drift.IdentityFromEntry(item.Decision)
		key := pairKeyOf(item.Decision)
		at, err := time.Parse(time.RFC3339, item.Decision.Timestamp)
		if err != nil {
			unscorable++
			continue
		}
		// Walk forward on both derived dimensions at once: inter-arrival against
		// the previous connection for this pair as the replay has seen it so
		// far, concurrency at this same instant. One parse serves both, so they
		// cannot disagree about when this connection happened.
		score := baseline.ScoreAgainst(identity, item.Decision.Host, item,
			lastSeen[key], index.At(at, item.Decision.ConnID))
		lastSeen[key] = at
		if !score.Scored {
			unscorable++
			continue
		}
		if math.IsInf(score.Distance, 1) {
			infinite++
			continue
		}
		scores = append(scores, score.Distance)
	}
	return scores, infinite, unscorable
}

// pairKeyOf follows drift's identity and host bucketing so the replay's
// last-seen state advances for exactly the pair whose cloud is being scored.
// It mirrors identityKey/hostKey/pairKey in internal/drift; those are
// unexported, and a mismatch would silently bucket the replay differently
// from the clouds it scores against.
func pairKeyOf(decision decisionlog.Entry) string {
	id := drift.IdentityFromEntry(decision)
	return strings.Join([]string{
		id.ExePath, id.ExeSHA256, id.TeamID, id.ExeBasename,
		strings.ToLower(decision.Host),
	}, "\x00")
}

func quantile(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return math.NaN()
	}
	return sorted[int(q*float64(len(sorted)-1))]
}

func baseOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}
