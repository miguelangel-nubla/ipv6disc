package plugins

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPollerRun(t *testing.T) {
	var p Poller
	ctx, cancel := context.WithCancel(context.Background())
	runs := 0
	errs := 0
	done := make(chan error)
	go func() {
		done <- p.Run(ctx, time.Millisecond, func() (int, error) {
			runs++
			if runs == 3 {
				cancel()
				return 1, errors.New("boom")
			}
			return 2, nil
		}, func(error) { errs++ })
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	stats := p.Stats()
	if runs != 3 || errs != 1 || stats["discovery_count"] != 5 || stats["last_error"] != "boom" {
		t.Errorf("runs %d, errors %d, stats %v", runs, errs, stats)
	}
}

func TestParseSSHConfig(t *testing.T) {
	cfg, err := ParseSSHConfig("linux", "60s,192.0.2.1,user,pass,/key")
	if err != nil || cfg.Interval != time.Minute || cfg.Address != "192.0.2.1" || cfg.Username != "user" || cfg.Password != "pass" || cfg.IdentityFile != "/key" {
		t.Errorf("got %+v, %v", cfg, err)
	}
	for _, bad := range []string{"192.0.2.1,user", "soon,192.0.2.1,user,pass", "0s,192.0.2.1,user,pass"} {
		if _, err := ParseSSHConfig("linux", bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}
