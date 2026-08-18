package drift

import (
	"math"
	"testing"
)

func cloudOn(dim Dim, values ...float64) []Point {
	cloud := make([]Point, len(values))
	for i, value := range values {
		cloud[i][dim] = value
	}
	return cloud
}

func TestScaleForUsesRobustShrunkenNonzeroSpread(t *testing.T) {
	pooled := Scale{}
	pooled[DimBytesUp] = 10
	robust := ScaleFor(cloudOn(DimBytesUp, 1, 2, 3, 4, 100), Scale{})
	if robust[DimBytesUp] > 3 {
		t.Fatalf("outlier-sensitive scale %v", robust[DimBytesUp])
	}
	sparse := ScaleFor(cloudOn(DimBytesUp, 1, 1.1), pooled)
	dense := ScaleFor(cloudOn(DimBytesUp, 1, 1.1, 1, 1.1, 1, 1.1, 1, 1.1, 1, 1.1, 1, 1.1, 1, 1.1, 1, 1.1, 1, 1.1, 1, 1.1), pooled)
	if sparse[DimBytesUp] <= dense[DimBytesUp] {
		t.Fatalf("sparse=%v dense=%v", sparse[DimBytesUp], dense[DimBytesUp])
	}
	zero := ScaleFor(cloudOn(DimBytesUp, 5, 5), Scale{})
	for dim := Dim(0); dim < numDims; dim++ {
		if zero[dim] <= 0 {
			t.Fatalf("scale[%d]=%v", dim, zero[dim])
		}
	}
}

func TestScaleForEmptyCloudUsesPooledScale(t *testing.T) {
	pooled := Scale{}
	pooled[DimBytesUp] = 7
	if got := ScaleFor(nil, pooled); got[DimBytesUp] != 7 {
		t.Fatalf("scale=%v", got[DimBytesUp])
	}
}

func TestScaleForIsContinuousInObservationCount(t *testing.T) {
	pooled := Scale{}
	pooled[DimUserActive] = 1
	var previous float64
	for n := 1; n <= 60; n++ {
		got := ScaleFor(cloudOn(DimUserActive, make([]float64, n)...), pooled)[DimUserActive]
		if got < minimumScale[DimUserActive] {
			t.Fatalf("n=%d scale=%v below physical floor=%v", n, got, minimumScale[DimUserActive])
		}
		if n > 1 && math.Abs(got-previous) > 0.1 {
			t.Fatalf("scale jumped from %v to %v", previous, got)
		}
		previous = got
	}
}

func TestScaleForZeroMADDoesNotMakeFixedDeviationDependOnCloudSize(t *testing.T) {
	var probe Point
	probe[DimUserActive] = 0.5
	var first, last float64
	for _, n := range []int{2, 10, 100, maxCloudPoints} {
		cloud := cloudOn(DimUserActive, make([]float64, n)...)
		distance := ScorePoint(probe, cloud, ScaleFor(cloud, Scale{})).Distance
		if first == 0 {
			first = distance
		}
		last = distance
	}
	if first != last {
		t.Fatalf("fixed deviation changed with cloud size: first=%v last=%v", first, last)
	}
}
