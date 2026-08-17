package daemon

import (
	"regexp"
	"testing"
)

func TestNewConnID_IsUniqueHex(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{16}$`)
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := newConnID()
		if !re.MatchString(id) {
			t.Fatalf("conn id %q is not 16 lowercase hex characters", id)
		}
		if seen[id] {
			t.Fatalf("conn id %q repeated; flow records would correlate to the wrong decision", id)
		}
		seen[id] = true
	}
}
