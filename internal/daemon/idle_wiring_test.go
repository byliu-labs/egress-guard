package daemon

import (
	"errors"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/idle"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

func TestDecideBranch_StampsUserActive(t *testing.T) {
	stub := idle.NewStub()
	stub.SetActive(false)
	d := newDaemonForBranch(t, stubAlwaysDeny{}, nil)
	d.opts.Idle = stub

	_, entry := d.decideBranch("deny.example", nil, testProcInfo(), signature.SignedIdentity{})
	if entry.UserActive == nil {
		t.Fatal("UserActive not stamped; the bit never reaches the log")
	}
	if *entry.UserActive {
		t.Error("UserActive = true, want false: the stub reports idle")
	}
}

func TestDecideBranch_ProbeFailureOmitsBitAndDoesNotChangeVerdict(t *testing.T) {
	stub := idle.NewStub()
	stub.SetError(errors.New("ioreg exploded"))
	withProbe := newDaemonForBranch(t, stubAlwaysDeny{}, nil)
	withProbe.opts.Idle = stub
	gotOutcome, gotEntry := withProbe.decideBranch("deny.example", nil, testProcInfo(), signature.SignedIdentity{})

	noProbe := newDaemonForBranch(t, stubAlwaysDeny{}, nil)
	wantOutcome, _ := noProbe.decideBranch("deny.example", nil, testProcInfo(), signature.SignedIdentity{})
	if gotEntry.UserActive != nil {
		t.Error("a failed probe must leave UserActive absent, not false")
	}
	if gotOutcome != wantOutcome {
		t.Errorf("outcome changed when the idle probe failed: %v vs %v", gotOutcome, wantOutcome)
	}
}

func TestDecideBranch_NoSampleAndNilProbeOmitBit(t *testing.T) {
	stub := idle.NewStub()
	stub.SetError(idle.ErrNoSample)
	for name, reporter := range map[string]IdleReporter{"no sample": stub, "nil": nil} {
		t.Run(name, func(t *testing.T) {
			d := newDaemonForBranch(t, stubAlwaysDeny{}, nil)
			d.opts.Idle = reporter
			_, entry := d.decideBranch("deny.example", nil, testProcInfo(), signature.SignedIdentity{})
			if entry.UserActive != nil {
				t.Errorf("UserActive = %v, want absent", *entry.UserActive)
			}
		})
	}
}

func testProcInfo() procid.ProcInfo {
	return procid.ProcInfo{PID: 1, Exe: "/usr/bin/curl", Comm: "curl"}
}
