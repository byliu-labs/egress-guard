package drift

import (
	"math"
	"sort"
)

// k is how many nearest historical points the distance averages over.
const k = 5

const dominantDimensions = 2

// Score is the result of comparing one connection to its pair's history.
// Distance is +Inf when the history is empty.
type Score struct {
	Distance   float64
	Neighbours int
	Dominant   []Dim
	Nearest    Point
	HasNearest bool
}

// ScorePoint returns the scaled distance from p to the k nearest points of
// cloud, plus the dimensions that dominate that distance.
func ScorePoint(p Point, cloud []Point, s Scale) Score {
	if len(cloud) == 0 {
		return Score{Distance: math.Inf(1)}
	}

	type neighbour struct {
		d float64
		i int
	}
	all := make([]neighbour, len(cloud))
	for i, q := range cloud {
		all[i] = neighbour{d: scaledDistance(p, q, s), i: i}
	}
	sort.Slice(all, func(a, b int) bool { return all[a].d < all[b].d })

	n := k
	if n > len(all) {
		n = len(all)
	}
	sum := 0.0
	for _, neighbour := range all[:n] {
		sum += neighbour.d
	}

	nearest := cloud[all[0].i]
	return Score{
		Distance:   sum / float64(n),
		Neighbours: n,
		Dominant:   dominantAgainst(p, nearest, s),
		Nearest:    nearest,
		HasNearest: true,
	}
}

func scaledDistance(a, b Point, s Scale) float64 {
	sum := 0.0
	for d := Dim(0); d < numDims; d++ {
		diff := (a[d] - b[d]) / s[d]
		sum += diff * diff
	}
	return math.Sqrt(sum)
}

func dominantAgainst(p, nearest Point, s Scale) []Dim {
	type contribution struct {
		d Dim
		v float64
	}
	all := make([]contribution, 0, numDims)
	for d := Dim(0); d < numDims; d++ {
		diff := (p[d] - nearest[d]) / s[d]
		all = append(all, contribution{d: d, v: diff * diff})
	}
	sort.Slice(all, func(a, b int) bool { return all[a].v > all[b].v })

	out := make([]Dim, 0, dominantDimensions)
	seen := map[string]bool{}
	for _, contribution := range all {
		if len(out) == dominantDimensions || contribution.v == 0 {
			break
		}
		if seen[DimNames[contribution.d]] {
			continue
		}
		seen[DimNames[contribution.d]] = true
		out = append(out, contribution.d)
	}
	return out
}
