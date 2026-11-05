package mikrotik

import "testing"

func TestNeighborInUse(t *testing.T) {
	for status, want := range map[string]bool{
		"reachable": true, "delay": true, "probe": true, "noarp": true, "": true,
		"stale": false, "failed": false,
	} {
		if got := neighborInUse(status); got != want {
			t.Errorf("neighborInUse(%q) = %v, want %v", status, got, want)
		}
	}
}
