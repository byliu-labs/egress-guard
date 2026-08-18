// Command drift-inspect rebuilds behaviour clouds from a decision log and
// reports what they contain. It is a read-only maintainer tool: it opens the
// log, builds a baseline in memory, prints numbers, and writes nothing.
//
// Its purpose is to demonstrate the retroactive property that motivates
// deriving dimensions instead of collecting them — history written before a
// dimension existed still yields that dimension.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/drift"
)

type report struct {
	Entries               int
	Connections           int
	Pairs                 int
	Points                int
	PointsWithConcurrency int
	MaxConcurrency        float64
}

func inspect(logPath string) (report, error) {
	var rep report
	entries, err := decisionlog.Read(logPath)
	if err != nil {
		return rep, fmt.Errorf("read %s: %w", logPath, err)
	}
	rep.Entries = len(entries)
	rep.Connections = len(decisionlog.Join(entries))

	baseline := drift.BuildBaseline(&catalog.Catalog{}, entries)
	for _, pair := range baseline.Pairs() {
		cloud, _ := baseline.CloudFor(pair.Identity, pair.Host)
		if len(cloud) == 0 {
			continue
		}
		rep.Pairs++
		for _, point := range cloud {
			rep.Points++
			if point[drift.DimConcurrency] > 0 {
				rep.PointsWithConcurrency++
			}
			if point[drift.DimConcurrency] > rep.MaxConcurrency {
				rep.MaxConcurrency = point[drift.DimConcurrency]
			}
		}
	}
	return rep, nil
}

func main() {
	def := ""
	if home, err := os.UserHomeDir(); err == nil {
		def = filepath.Join(home, ".local", "state", "egress-guard", "decisions.log")
	}
	logPath := flag.String("log", def, "path to decisions.log")
	flag.Parse()

	rep, err := inspect(*logPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("log entries:              %d\n", rep.Entries)
	fmt.Printf("connections:              %d\n", rep.Connections)
	fmt.Printf("pairs with a cloud:       %d\n", rep.Pairs)
	fmt.Printf("points in clouds:         %d\n", rep.Points)
	fmt.Printf("points with concurrency:  %d\n", rep.PointsWithConcurrency)
	fmt.Printf("max concurrency (log1p):  %.3f\n", rep.MaxConcurrency)
	if rep.Points > 0 && rep.PointsWithConcurrency == 0 {
		fmt.Println()
		fmt.Println("WARNING: no historical point carries concurrency. Either this log has")
		fmt.Println("no overlapping connections, or the dimension is not being derived.")
	}
}
