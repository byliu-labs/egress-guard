package drift

import (
	"math"
	"sort"
)

// Scale normalizes each behavioural dimension before distances are compared.
type Scale [numDims]float64

const shrinkageWeight = 10.0

// minimumScale bounds each axis in its native, transformed units before
// shrinkage. A zero-MAD cron-like pair must not become arbitrarily sensitive
// merely because it has accumulated more history.
var minimumScale = Scale{
	DimBytesUp: 0.1, DimBytesDown: 0.1, DimRatio: 0.1, DimDuration: 0.1,
	DimHourSin: 0.1, DimHourCos: 0.1, DimUserActive: 0.5, DimInterArrival: 0.1,
}

// ScaleFor estimates robust per-pair spread and continuously shrinks it toward
// a pooled estimate when that pair has little history.
func ScaleFor(cloud []Point, pooled Scale) Scale {
	var scale Scale
	weight := float64(len(cloud)) / (float64(len(cloud)) + shrinkageWeight)
	for dim := Dim(0); dim < numDims; dim++ {
		base := pooled[dim]
		if base < minimumScale[dim] {
			base = minimumScale[dim]
		}
		own := madAlong(cloud, dim)
		if own < minimumScale[dim] {
			own = minimumScale[dim]
		}
		value := weight*own + (1-weight)*base
		scale[dim] = value
	}
	return scale
}

func madAlong(cloud []Point, dim Dim) float64 {
	values := make([]float64, len(cloud))
	for i, point := range cloud {
		values[i] = point[dim]
	}
	center := median(values)
	for i, value := range values {
		values[i] = math.Abs(value - center)
	}
	return median(values)
}

func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

// PooledScale supplies a safe starting scale for previously unseen pairs.
func PooledScale(clouds [][]Point) Scale {
	var all []Point
	for _, cloud := range clouds {
		all = append(all, cloud...)
	}
	var scale Scale
	for dim := Dim(0); dim < numDims; dim++ {
		scale[dim] = madAlong(all, dim)
		if scale[dim] < minimumScale[dim] {
			scale[dim] = minimumScale[dim]
		}
	}
	return scale
}
