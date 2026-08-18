package drift

import (
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

const maxCloudPoints = 512

type clouds struct {
	points map[string][]Point
	last   map[string]time.Time
	pooled Scale
}

func newClouds() *clouds {
	return &clouds{points: map[string][]Point{}, last: map[string]time.Time{}}
}

func (cloud *clouds) add(key string, joined decisionlog.Joined) {
	timestamp, err := time.Parse(time.RFC3339, joined.Decision.Timestamp)
	if err != nil {
		return
	}
	point, ok := PointFrom(joined, cloud.last[key])
	cloud.last[key] = timestamp
	if !ok {
		return
	}
	points := append(cloud.points[key], point)
	if len(points) > maxCloudPoints {
		points = points[len(points)-maxCloudPoints:]
	}
	cloud.points[key] = points
}

func (cloud *clouds) finish() {
	all := make([][]Point, 0, len(cloud.points))
	for _, points := range cloud.points {
		all = append(all, points)
	}
	cloud.pooled = PooledScale(all)
}

func (baseline *Baseline) CloudFor(identity catalog.Identity, host string) ([]Point, Scale) {
	if baseline == nil || baseline.clouds == nil {
		return nil, ScaleFor(nil, Scale{})
	}
	points := baseline.clouds.points[pairKey(identityKey(identity), hostKey(host))]
	return points, ScaleFor(points, baseline.clouds.pooled)
}

func (baseline *Baseline) LastSeenFor(identity catalog.Identity, host string) time.Time {
	if baseline == nil || baseline.clouds == nil {
		return time.Time{}
	}
	return baseline.clouds.last[pairKey(identityKey(identity), hostKey(host))]
}
