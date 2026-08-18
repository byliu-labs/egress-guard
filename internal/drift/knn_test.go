package drift

import (
	"math"
	"testing"
)

func unitScale() Scale {
	var s Scale
	for d := Dim(0); d < numDims; d++ {
		s[d] = 1
	}
	return s
}

func TestScorePoint_EmptyCloudIsUnbounded(t *testing.T) {
	got := ScorePoint(Point{}, nil, unitScale())
	if !math.IsInf(got.Distance, 1) {
		t.Errorf("Distance = %v, want +Inf for an empty history", got.Distance)
	}
	if got.Neighbours != 0 {
		t.Errorf("Neighbours = %d, want 0", got.Neighbours)
	}
	if got.HasNearest {
		t.Error("HasNearest = true with no history")
	}
}

func TestScorePoint_PointInsideItsCloudScoresNear(t *testing.T) {
	cloud := cloudOn(DimBytesUp, 1, 1.1, 0.9, 1.05, 0.95)
	var p Point
	p[DimBytesUp] = 1.02
	got := ScorePoint(p, cloud, unitScale())
	if got.Distance > 0.5 {
		t.Errorf("Distance = %v; a point inside its own cloud must score near", got.Distance)
	}
}

func TestScorePoint_FarPointScoresFar(t *testing.T) {
	cloud := cloudOn(DimBytesUp, 1, 1.1, 0.9, 1.05, 0.95)
	var p Point
	p[DimBytesUp] = 40
	got := ScorePoint(p, cloud, unitScale())
	if got.Distance < 10 {
		t.Errorf("Distance = %v; a point far from its cloud must score far", got.Distance)
	}
}

func TestScorePoint_CatchesInteractionAMarginalScoreWouldMiss(t *testing.T) {
	var cloud []Point
	for i := 0; i < 20; i++ {
		var day Point
		day[DimBytesUp], day[DimHourSin], day[DimHourCos] = 15, 0, 1
		var night Point
		night[DimBytesUp], night[DimHourSin], night[DimHourCos] = 9, 0, -1
		cloud = append(cloud, day, night)
	}
	var probe Point
	probe[DimBytesUp], probe[DimHourSin], probe[DimHourCos] = 15, 0, -1

	got := ScorePoint(probe, cloud, unitScale())
	if got.Distance < 1 {
		t.Fatalf("Distance = %v; 4MB at 3am must be anomalous even though 4MB is normal and 3am is normal", got.Distance)
	}
}

func TestScorePoint_AttributesTheDominantDimension(t *testing.T) {
	cloud := cloudOn(DimBytesUp, 1, 1.1, 0.9, 1.05, 0.95)
	var p Point
	p[DimBytesUp] = 40
	got := ScorePoint(p, cloud, unitScale())
	if len(got.Dominant) == 0 {
		t.Fatal("no dominant dimension reported; the explanation cannot be written")
	}
	if got.Dominant[0] != DimBytesUp {
		t.Errorf("Dominant[0] = %s, want %s", DimNames[got.Dominant[0]], DimNames[DimBytesUp])
	}
}

func TestScorePoint_WideScaleForgivesWideVariation(t *testing.T) {
	cloud := cloudOn(DimBytesUp, 1, 5, 9, 13, 17)
	var p Point
	p[DimBytesUp] = 21

	tight := unitScale()
	wide := unitScale()
	wide[DimBytesUp] = 8

	if ScorePoint(p, cloud, wide).Distance >= ScorePoint(p, cloud, tight).Distance {
		t.Error("a wider scale must forgive the same deviation")
	}
}

func TestScorePoint_HandlesCloudSmallerThanK(t *testing.T) {
	got := ScorePoint(Point{}, cloudOn(DimBytesUp, 1), unitScale())
	if math.IsInf(got.Distance, 1) {
		t.Error("a one-point cloud must yield a finite distance")
	}
	if got.Neighbours != 1 {
		t.Errorf("Neighbours = %d, want 1", got.Neighbours)
	}
}
