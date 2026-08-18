package drift

import (
	"math"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

func testJoined(ts string, up, down, duration int64, active *bool) decisionlog.Joined {
	return decisionlog.Joined{
		Decision: decisionlog.Entry{Timestamp: ts, UserActive: active},
		Flow:     decisionlog.Entry{BytesUp: up, BytesDown: down, DurationMS: duration},
		HasFlow:  true,
	}
}

func TestPointFromEncodesConnectionMetadata(t *testing.T) {
	yes := true
	p, ok := PointFrom(testJoined("2026-08-17T23:00:00Z", 1023, 4095, 250, &yes), time.Time{})
	if !ok || p[DimBytesUp] != math.Log1p(1023) || p[DimBytesDown] != math.Log1p(4095) || p[DimUserActive] != 1 {
		t.Fatalf("PointFrom = %v, %v", p, ok)
	}
	if p[DimInterArrival] != math.Log1p(unknownInterArrivalSeconds) {
		t.Fatalf("first inter-arrival = %v", p[DimInterArrival])
	}
}

func TestPointFromUsesCyclicHourAndNeutralUnknownActivity(t *testing.T) {
	a, _ := PointFrom(testJoined("2026-08-17T23:00:00Z", 1, 1, 1, nil), time.Time{})
	b, _ := PointFrom(testJoined("2026-08-18T01:00:00Z", 1, 1, 1, nil), time.Time{})
	mid, _ := PointFrom(testJoined("2026-08-17T12:00:00Z", 1, 1, 1, nil), time.Time{})
	if a[DimUserActive] != 0.5 || math.Hypot(a[DimHourSin]-b[DimHourSin], a[DimHourCos]-b[DimHourCos]) >= math.Hypot(a[DimHourSin]-mid[DimHourSin], a[DimHourCos]-mid[DimHourCos]) {
		t.Fatalf("cyclic/neutral encoding failed: %v %v %v", a, b, mid)
	}
}

func TestPointFromRejectsIncompleteRecordsAndUsesPairGap(t *testing.T) {
	noFlow := testJoined("2026-08-17T14:01:00Z", 1, 1, 1, nil)
	noFlow.HasFlow = false
	if _, ok := PointFrom(noFlow, time.Time{}); ok {
		t.Fatal("missing flow became a point")
	}
	bad := testJoined("not-a-time", 1, 1, 1, nil)
	if _, ok := PointFrom(bad, time.Time{}); ok {
		t.Fatal("bad timestamp became a point")
	}
	prev := time.Date(2026, 8, 17, 14, 0, 0, 0, time.UTC)
	p, _ := PointFrom(testJoined("2026-08-17T14:01:00Z", 1, 1, 1, nil), prev)
	if p[DimInterArrival] != math.Log1p(60) {
		t.Fatalf("gap = %v", p[DimInterArrival])
	}
}

func TestPointFromRejectsNegativeFlowMetadata(t *testing.T) {
	for _, test := range []decisionlog.Joined{
		testJoined("2026-08-17T14:00:00Z", -2, 1, 1, nil),
		testJoined("2026-08-17T14:00:00Z", 1, -2, 1, nil),
		testJoined("2026-08-17T14:00:00Z", 1, 1, -1, nil),
	} {
		if _, ok := PointFrom(test, time.Time{}); ok {
			t.Fatalf("invalid flow became a point: %+v", test.Flow)
		}
	}
}
