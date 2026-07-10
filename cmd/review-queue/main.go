// cmd/review-queue is a maintainer tool for the telemetry review queue.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/reviewqueue"
	"github.com/byliu-labs/egress-guard/internal/telemetry"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "list":
		err = list(os.Args[2:])
	case "evidence":
		err = evidence(os.Args[2:])
	case "approve":
		err = approve(os.Args[2:])
	case "reject":
		err = reject(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "review-queue: unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "review-queue: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `review-queue - maintainer tool for telemetry candidates

Usage:
  review-queue list --queue <path> [--burst]
  review-queue evidence --queue <path> --exe <basename> --team <id> --bundle <id> --signed --host <host> --verdict allow|deny --evidence <text> --confidence high|medium
  review-queue approve --queue <path> --catalog <path> --exe <basename> --team <id> --bundle <id> --signed --host <host> --verdict allow|deny
  review-queue reject --queue <path> --exe <basename> --team <id> --bundle <id> --signed --host <host> --verdict allow|deny --reason <text>
`)
}

func list(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	queuePath := fs.String("queue", "", "path to review queue JSONL")
	burstOnly := fs.Bool("burst", false, "show only burst-flagged candidates")
	fs.Parse(args)

	q, err := reviewqueue.Open(*queuePath)
	if err != nil {
		return err
	}
	defer q.Close()
	q.DetectBursts(reviewqueue.DefaultBurstThreshold, reviewqueue.DefaultBurstWindow)
	for _, c := range q.Candidates() {
		if *burstOnly && !c.Burst {
			continue
		}
		fmt.Printf("%-6d %-10s %-30s %-6s %-30s burst=%v evidence=%q\n",
			c.Count,
			c.Status,
			formatIdentity(c.Key.Identity),
			c.Key.Verdict,
			c.Key.Host,
			c.Burst,
			c.Evidence)
	}
	return nil
}

func evidence(args []string) error {
	fs := flag.NewFlagSet("evidence", flag.ExitOnError)
	queuePath := fs.String("queue", "", "path to review queue JSONL")
	id := identityFlagSet(fs)
	host := fs.String("host", "", "candidate host")
	verdict := fs.String("verdict", "", "allow|deny")
	ev := fs.String("evidence", "", "evidence text")
	confidence := fs.String("confidence", "", "high|medium")
	fs.Parse(args)

	q, err := reviewqueue.Open(*queuePath)
	if err != nil {
		return err
	}
	defer q.Close()
	key := reviewqueue.Key{
		Identity: id.identity(),
		Host:     *host,
		Verdict:  *verdict,
	}
	return q.SetEvidence(key, *ev, catalog.Confidence(*confidence))
}

func approve(args []string) error {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	queuePath := fs.String("queue", "", "path to review queue JSONL")
	catPath := fs.String("catalog", "", "path to baseline catalog TOML")
	id := identityFlagSet(fs)
	host := fs.String("host", "", "candidate host")
	verdict := fs.String("verdict", "", "allow|deny")
	fs.Parse(args)

	q, err := reviewqueue.Open(*queuePath)
	if err != nil {
		return err
	}
	defer q.Close()

	cat, err := catalog.LoadFile(*catPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		cat, err = catalog.Load(nil)
		if err != nil {
			return err
		}
	}

	key := reviewqueue.Key{
		Identity: id.identity(),
		Host:     *host,
		Verdict:  *verdict,
	}
	entry, err := q.Approve(cat, key)
	if err != nil {
		return err
	}
	b, err := cat.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*catPath, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("approved: %+v\n", entry)
	return nil
}

func reject(args []string) error {
	fs := flag.NewFlagSet("reject", flag.ExitOnError)
	queuePath := fs.String("queue", "", "path to review queue JSONL")
	id := identityFlagSet(fs)
	host := fs.String("host", "", "candidate host")
	verdict := fs.String("verdict", "", "allow|deny")
	reason := fs.String("reason", "", "rejection reason")
	fs.Parse(args)

	q, err := reviewqueue.Open(*queuePath)
	if err != nil {
		return err
	}
	defer q.Close()
	key := reviewqueue.Key{
		Identity: id.identity(),
		Host:     *host,
		Verdict:  *verdict,
	}
	return q.Reject(key, *reason)
}

func seedOneReport(queuePath, exe, team, host, verdict, uuid string) error {
	q, err := reviewqueue.Open(queuePath)
	if err != nil {
		return err
	}
	defer q.Close()
	id := catalog.Identity{ExeBasename: exe, TeamID: team}
	return q.Ingest(telemetry.NewReport(uuid, id, host, verdict))
}

type identityFlags struct {
	exe    *string
	team   *string
	bundle *string
	signed *bool
}

func identityFlagSet(fs *flag.FlagSet) identityFlags {
	return identityFlags{
		exe:    fs.String("exe", "", "identity executable basename"),
		team:   fs.String("team", "", "identity team id"),
		bundle: fs.String("bundle", "", "identity bundle id"),
		signed: fs.Bool("signed", false, "identity required a valid signature"),
	}
}

func (f identityFlags) identity() catalog.Identity {
	return catalog.Identity{
		ExeBasename:    *f.exe,
		TeamID:         *f.team,
		BundleID:       *f.bundle,
		SignedRequired: *f.signed,
	}
}

func formatIdentity(id catalog.Identity) string {
	return fmt.Sprintf("exe=%s team=%s bundle=%s signed=%v", id.ExeBasename, id.TeamID, id.BundleID, id.SignedRequired)
}
