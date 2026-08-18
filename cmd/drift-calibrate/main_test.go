package main

import "testing"

func TestQuantileAndBaseOf(t *testing.T) {
	if got := quantile([]float64{1, 2, 3, 4, 5}, 0.9); got != 4 {
		t.Fatalf("quantile = %v", got)
	}
	if got := baseOf("/usr/bin/git"); got != "git" {
		t.Fatalf("baseOf = %q", got)
	}
}
