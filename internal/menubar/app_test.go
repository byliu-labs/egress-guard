//go:build darwin

package menubar

import "testing"

func TestLastIndexTwoSpaces(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"10:02  evil.example", 5},
		{"no delimiter", -1},
		{"a  b  c", 4},
	}
	for _, c := range cases {
		if got := lastIndexTwoSpaces(c.in); got != c.want {
			t.Errorf("lastIndexTwoSpaces(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
