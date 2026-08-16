package prompt

import (
	"fmt"
	"strings"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/drift"
	"github.com/byliu-labs/egress-guard/internal/explain"
)

const (
	catalogFactLabel = "[CATALOG FACT -- verified]"
	catalogHintLabel = "[CATALOG HINT -- advisory, unverified identity]"
	opinionLabel     = "[MODEL GUESS -- advisory, unverified]"
)

// RenderPrompt builds notifier text for an unknown or drifted connection.
func RenderPrompt(req Request) string {
	var b strings.Builder

	fmt.Fprintf(&b, "%s wants to connect to %s.\n", req.Proc.Comm, req.Host)
	if req.Drift.Class == drift.ClassDrift {
		fmt.Fprintf(&b, "Drift: %s (first seen %s)\n", req.Drift.Reason, formatFirstSeen(req.Drift.FirstSeen))
	}
	if req.Persistence != nil {
		fmt.Fprintf(&b, "Persistence: %s (%s)\n", req.Persistence.Kind, req.Persistence.Label)
	}

	hasFact := req.CatalogMatch.Found
	hasOpinion := req.Opinion != nil
	if hasFact {
		b.WriteString(renderCatalogFact(req.CatalogMatch.Entry))
	}
	if hasOpinion {
		b.WriteString(renderOpinion(*req.Opinion))
	}
	if !hasFact && !hasOpinion {
		b.WriteString("No catalog match and no model opinion -- reviewing based on process and destination only.\n")
	}

	b.WriteString("Allow this destination?")
	return b.String()
}

func renderCatalogFact(e catalog.Entry) string {
	if e.Confidence == catalog.ConfidenceMedium {
		return fmt.Sprintf("%s %s\n", catalogHintLabel, e.Explanation)
	}
	return fmt.Sprintf("%s %s\n", catalogFactLabel, e.Explanation)
}

func renderOpinion(o explain.Explanation) string {
	return fmt.Sprintf("%s (%s confidence):\nModel says: %s\nEvidence: %s\n", opinionLabel, o.Confidence, sanitizeModelText(o.Text), sanitizeModelText(o.Evidence))
}

func sanitizeModelText(s string) string {
	s = strings.ReplaceAll(s, catalogFactLabel, "[catalog fact label removed]")
	s = strings.ReplaceAll(s, catalogHintLabel, "[catalog hint label removed]")
	s = strings.ReplaceAll(s, opinionLabel, "[model guess label removed]")
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = "  " + line
	}
	return strings.Join(lines, "\n")
}

func formatFirstSeen(t time.Time) string {
	if t.IsZero() {
		return "just now"
	}
	return t.Format(time.RFC3339)
}
