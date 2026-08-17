package prompt

import (
	"fmt"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

// RatifyWriter persists AllowAlways/DenyAlways prompt choices as user-layer
// catalog entries. Hashless entries remain prompt context, not silent authority.
type RatifyWriter interface {
	Ratify(e catalog.Entry) error
}

func catalogEntryFor(req Request, allow bool) catalog.Entry {
	host := ratifiedHost(req)
	e := catalog.Entry{
		SchemaVersion: catalog.CurrentSchemaVersion,
		Identity:      req.Drift.Identity,
		Confidence:    ratifiedConfidence(req.Drift.Identity),
		Layer:         "user",
		Evidence:      fmt.Sprintf("ratified by user via drift prompt at %s", time.Now().UTC().Format(time.RFC3339)),
	}
	if allow {
		e.ExpectedDestinations = []catalog.Destination{{Host: host, Why: "user-ratified allow via drift prompt"}}
		if catalog.HasDecisionPin(e.Identity) {
			e.Explanation = fmt.Sprintf("%s is allowed to reach %s (ratified by user)", req.Proc.Comm, host)
		} else {
			e.Explanation = fmt.Sprintf("%s was allowed once to reach %s, but no executable identity pin was available; this entry is context-only", req.Proc.Comm, host)
		}
	} else {
		e.Never = []string{host}
		e.Explanation = fmt.Sprintf("%s must never reach %s (ratified by user)", req.Proc.Comm, host)
	}
	return e
}

func ratifiedHost(req Request) string {
	if req.Host != "" {
		return req.Host
	}
	return req.RegDom
}

func ratifiedConfidence(id catalog.Identity) catalog.Confidence {
	if id.TeamID == "" && id.BundleID == "" {
		return catalog.ConfidenceMedium
	}
	return catalog.ConfidenceHigh
}
