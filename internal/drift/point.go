package drift

import (
	"math"
	"time"

	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

// Dim indexes a continuous behavioural dimension. Identity and host select a
// cloud; they are not coordinates with artificial geometric distance.
type Dim int

const (
	DimBytesUp Dim = iota
	DimBytesDown
	DimRatio
	DimDuration
	DimHourSin
	DimHourCos
	DimUserActive
	DimInterArrival
	numDims
)

var DimNames = [numDims]string{
	"bytes sent", "bytes received", "up:down ratio", "duration",
	"hour of day", "hour of day", "whether you were at the keyboard",
	"time since the last connection to this host",
}

// Point is one connection in the continuous behaviour space.
type Point [numDims]float64

const unknownInterArrivalSeconds = 3600
const unknownUserActive = 0.5

// PointFrom builds a complete point from a decision/flow pair. Missing flow
// metadata remains unknown rather than being fabricated as zero.
func PointFrom(j decisionlog.Joined, prev time.Time) (Point, bool) {
	var point Point
	if !j.HasFlow || j.Flow.BytesUp < 0 || j.Flow.BytesDown < 0 || j.Flow.DurationMS < 0 {
		return point, false
	}
	timestamp, err := time.Parse(time.RFC3339, j.Decision.Timestamp)
	if err != nil {
		return point, false
	}
	up, down := float64(j.Flow.BytesUp), float64(j.Flow.BytesDown)
	point[DimBytesUp] = math.Log1p(up)
	point[DimBytesDown] = math.Log1p(down)
	point[DimRatio] = math.Log1p(up) - math.Log1p(down)
	point[DimDuration] = math.Log1p(float64(j.Flow.DurationMS))
	dayFraction := (float64(timestamp.Hour()) + float64(timestamp.Minute())/60) / 24
	point[DimHourSin] = math.Sin(2 * math.Pi * dayFraction)
	point[DimHourCos] = math.Cos(2 * math.Pi * dayFraction)
	point[DimUserActive] = unknownUserActive
	if j.Decision.UserActive != nil {
		if *j.Decision.UserActive {
			point[DimUserActive] = 1
		} else {
			point[DimUserActive] = 0
		}
	}
	gap := float64(unknownInterArrivalSeconds)
	if !prev.IsZero() && timestamp.After(prev) {
		gap = timestamp.Sub(prev).Seconds()
	}
	point[DimInterArrival] = math.Log1p(gap)
	for _, value := range point {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return Point{}, false
		}
	}
	return point, true
}
