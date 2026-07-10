package prompt

import (
	"context"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/procid"
)

// TestCoalescer_SameRegDomGroupedWithin60s asserts that two prompts for the
// same registered domain within the window share one notifier call.
func TestCoalescer_SameRegDomGroupedWithin60s(t *testing.T) {
	inner := &StaticNotifier{A: ActionAllowOnce}
	c := NewCoalescer(inner, 60*time.Second, 5)

	req1 := Request{Proc: procid.ProcInfo{PID: 1}, Host: "a.s3.amazonaws.com", RegDom: "amazonaws.com"}
	req2 := Request{Proc: procid.ProcInfo{PID: 1}, Host: "b.s3.amazonaws.com", RegDom: "amazonaws.com"}

	a1, err := c.Notify(context.Background(), req1)
	if err != nil {
		t.Fatalf("first Notify: %v", err)
	}
	a2, err := c.Notify(context.Background(), req2)
	if err != nil {
		t.Fatalf("second Notify: %v", err)
	}
	if a1 != ActionAllowOnce || a2 != ActionAllowOnce {
		t.Errorf("expected both allow-once, got %v %v", a1, a2)
	}
	// Second request should reuse the first decision; inner call count = 1.
	if got := c.InnerCalls(); got != 1 {
		t.Errorf("inner notifier calls = %d, want 1 (coalesced)", got)
	}
}

// TestCoalescer_BurstAllowAlwaysDowngradedToOnce — regression for the P1
// caught in codex review: when the user clicks "Allow always" on a burst
// prompt (which shows no specific regdom), the cached action MUST NOT be
// returned as ActionAllowAlways for subsequent burst replays — that would
// trigger CoreDecider.persist() to silently allowlist every regdom from
// that pid for the next 60s, even though the user only saw a generic
// "process X is making many connections" dialog.
func TestCoalescer_BurstAllowAlwaysDowngradedToOnce(t *testing.T) {
	inner := &StaticNotifier{A: ActionAllowAlways}
	c := NewCoalescer(inner, 60*time.Second, 5)

	// Trip the burst with 6 distinct regdoms.
	hosts := []string{"a.com", "b.com", "c.com", "d.com", "e.com", "f.com"}
	var lastAction Action
	for _, host := range hosts {
		req := Request{Proc: procid.ProcInfo{PID: 100}, Host: host, RegDom: host}
		a, err := c.Notify(context.Background(), req)
		if err != nil {
			t.Fatalf("Notify(%s): %v", host, err)
		}
		lastAction = a
	}
	// The 6th call triggered the burst prompt. Inner returned AllowAlways
	// but Coalescer must downgrade it to AllowOnce so persist() doesn't fire.
	if lastAction != ActionAllowOnce {
		t.Errorf("burst-trigger return = %v, want ActionAllowOnce (downgraded from AllowAlways)", lastAction)
	}

	// Subsequent regdoms during the burst window must also come back as
	// ActionAllowOnce — never AllowAlways — so persist() never sees them.
	replay := Request{Proc: procid.ProcInfo{PID: 100}, Host: "g.com", RegDom: "g.com"}
	got, err := c.Notify(context.Background(), replay)
	if err != nil {
		t.Fatalf("burst replay: %v", err)
	}
	if got != ActionAllowOnce {
		t.Errorf("burst replay = %v, want ActionAllowOnce (downgraded)", got)
	}
}

// TestCoalescer_BurstDenyAlwaysDowngradedToDeny — Deny-side counterpart.
// User clicking "Deny always" on a burst prompt must NOT trigger persist()
// to silently denylist every regdom from that pid.
func TestCoalescer_BurstDenyAlwaysDowngradedToDeny(t *testing.T) {
	inner := &StaticNotifier{A: ActionDenyAlways}
	c := NewCoalescer(inner, 60*time.Second, 5)

	hosts := []string{"a.com", "b.com", "c.com", "d.com", "e.com", "f.com"}
	var lastAction Action
	for _, host := range hosts {
		req := Request{Proc: procid.ProcInfo{PID: 100}, Host: host, RegDom: host}
		a, _ := c.Notify(context.Background(), req)
		lastAction = a
	}
	if lastAction != ActionDeny {
		t.Errorf("burst-trigger return = %v, want ActionDeny (downgraded from DenyAlways)", lastAction)
	}

	replay := Request{Proc: procid.ProcInfo{PID: 100}, Host: "g.com", RegDom: "g.com"}
	got, _ := c.Notify(context.Background(), replay)
	if got != ActionDeny {
		t.Errorf("burst replay = %v, want ActionDeny (downgraded)", got)
	}
}

// TestCoalescer_BurstCollapsesAfterFiveDistinctRegDoms verifies that once a
// pid exceeds the burst threshold of distinct regdoms within the window, all
// subsequent prompts collapse onto a single cached burst decision.
func TestCoalescer_BurstCollapsesAfterFiveDistinctRegDoms(t *testing.T) {
	inner := &StaticNotifier{A: ActionDeny}
	c := NewCoalescer(inner, 60*time.Second, 5)

	hosts := []string{"a.com", "b.com", "c.com", "d.com", "e.com", "f.com", "g.com"}
	for _, host := range hosts {
		req := Request{Proc: procid.ProcInfo{PID: 100}, Host: host, RegDom: host}
		if _, err := c.Notify(context.Background(), req); err != nil {
			t.Fatalf("Notify(%s): %v", host, err)
		}
	}
	// Expect at most 6 inner calls: 5 distinct regdoms inside threshold + 1
	// burst prompt once the 6th distinct regdom trips the limit.
	if got := c.InnerCalls(); got > 6 {
		t.Errorf("inner calls = %d, want <=6 after burst (5 + 1 burst)", got)
	}
	if !c.InBurst(100) {
		t.Errorf("burst not flagged for pid=100")
	}
}
