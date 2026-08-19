package decisionlog

import (
	"strconv"
	"testing"
	"time"
)

func largeIndex(n int) (*ConcurrencyIndex, time.Time) {
	base := at("2026-08-17T14:00:00Z")
	js := make([]Joined, 0, n)
	for i := 0; i < n; i++ {
		js = append(js, conn("c"+strconv.Itoa(i),
			base.Add(time.Duration(i)*time.Second).Format(time.RFC3339), 5_000))
	}
	return BuildConcurrencyIndex(js), base
}

func BenchmarkConcurrencyIndex_At(b *testing.B) {
	idx, base := largeIndex(200_000)
	probe := base.Add(100_000 * time.Second)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx.At(probe, "")
	}
}
