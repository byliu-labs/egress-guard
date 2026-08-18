package decisionlog

import "testing"

func TestJoinPairsDecisionWithItsFlow(t *testing.T) {
	got := Join([]Entry{
		{Kind: KindDecision, ConnID: "c1", Host: "a.example"},
		{Kind: KindFlow, ConnID: "c1", BytesUp: 4096, BytesDown: 128, DurationMS: 250},
	})
	if len(got) != 1 {
		t.Fatalf("Join returned %d rows, want 1", len(got))
	}
	if got[0].Decision.Host != "a.example" || !got[0].HasFlow || got[0].Flow.BytesUp != 4096 {
		t.Fatalf("Join result = %+v, want paired decision and flow", got[0])
	}
}

func TestJoinKeepsDecisionWithoutFlowOrConnID(t *testing.T) {
	got := Join([]Entry{{Kind: KindDecision, ConnID: "c1"}, {Host: "legacy.example"}})
	if len(got) != 2 || got[0].HasFlow || got[1].HasFlow {
		t.Fatalf("Join result = %+v, want both decisions without flows", got)
	}
}

func TestJoinDropsOrphanFlowAndKeepsLastRepeatedFlow(t *testing.T) {
	got := Join([]Entry{
		{Kind: KindFlow, ConnID: "orphan", BytesUp: 99},
		{Kind: KindDecision, ConnID: "c1"},
		{Kind: KindFlow, ConnID: "c1", BytesUp: 1},
		{Kind: KindFlow, ConnID: "c1", BytesUp: 2},
	})
	if len(got) != 1 || !got[0].HasFlow || got[0].Flow.BytesUp != 2 {
		t.Fatalf("Join result = %+v, want one decision with final flow", got)
	}
}
