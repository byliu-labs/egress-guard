package drift

import "testing"

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
