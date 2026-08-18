// Command drift-calibrate reports the distribution of joint drift scores in a
// decision log. It is read-only: calibration chooses a future policy threshold.
package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"sort"

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
	var scores []float64
	infinite, unscorable := 0, 0
	for _, item := range joined[cut:] {
		identity := drift.IdentityFromEntry(item.Decision)
		score := baseline.ScoreLive(identity, item.Decision.Host, item, 0)
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
