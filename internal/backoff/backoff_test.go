package backoff

import (
	"testing"
	"time"
)

// The delay doubles with each error in a row, up to the longest, and a read that succeeds starts
// it over.
func TestDelay(t *testing.T) {
	var d Delay
	for i, want := range []time.Duration{5, 10, 20, 40, 80, 160, 320, 640, 1000, 1000, 1000} {
		if got := d.Next(); got != want*time.Millisecond {
			t.Errorf("error %d in a row: wait %s, want %s", i+1, got, want*time.Millisecond)
		}
	}
	d.Reset()
	if got := d.Next(); got != First {
		t.Errorf("after a reset: wait %s, want %s", got, First)
	}
}

func TestWait(t *testing.T) {
	var d Delay
	start := time.Now()
	d.Wait()
	d.Wait()
	if elapsed := time.Since(start); elapsed < 15*time.Millisecond {
		t.Errorf("two errors in a row waited %s, want 5ms and 10ms", elapsed)
	}
}
