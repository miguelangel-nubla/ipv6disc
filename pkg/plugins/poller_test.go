package plugins

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/internal/sshtest"
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

func TestRunSSH(t *testing.T) {
	server := sshtest.Start(t, "admin", "secret", func(command string) ([]byte, error) {
		if command == "fail" {
			return []byte("no"), errors.New("failed")
		}
		return []byte("ran " + command), nil
	})
	cfg := SSHConfig{Address: server.Address, Username: "admin", Password: "secret"}

	output, hostKey, err := RunSSH(context.Background(), cfg, "ip -6 neigh")
	if err != nil || string(output) != "ran ip -6 neigh" || hostKey != server.HostKey {
		t.Errorf("unpinned: got %q, %s, %v", output, hostKey, err)
	}

	cfg.HostKey = server.HostKey
	if _, _, err := RunSSH(context.Background(), cfg, "ip -6 neigh"); err != nil {
		t.Errorf("pinned: %v", err)
	}

	cfg.HostKey = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, _, err := RunSSH(context.Background(), cfg, "ip -6 neigh"); err == nil || !strings.Contains(err.Error(), "host key mismatch") {
		t.Errorf("pinned to another key: got %v", err)
	}
	if got := server.Commands(); len(got) != 2 {
		t.Errorf("the host ran %v: the command must not reach a host with another key", got)
	}

	cfg.HostKey = ""
	if _, _, err := RunSSH(context.Background(), cfg, "fail"); err == nil {
		t.Error("a failing command: want an error")
	}
	cfg.Password = "wrong"
	if _, _, err := RunSSH(context.Background(), cfg, "ip -6 neigh"); err == nil {
		t.Error("a wrong password: want an error")
	}
}

func TestRunSSHStopsWithItsContext(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	server := sshtest.Start(t, "admin", "secret", func(string) ([]byte, error) {
		<-release // a command that hangs
		return nil, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := RunSSH(ctx, SSHConfig{Address: server.Address, Username: "admin", Password: "secret"}, "hang")
	if err == nil || time.Since(start) > 5*time.Second {
		t.Errorf("got %v after %s, want an error once the context is done", err, time.Since(start))
	}
}

func TestParseSSHConfigHostKey(t *testing.T) {
	cfg, err := ParseSSHConfig("linux", "60s,192.0.2.1,user,pass,,SHA256:abc")
	if err != nil || cfg.HostKey != "SHA256:abc" || cfg.IdentityFile != "" {
		t.Errorf("got %+v, %v", cfg, err)
	}
	for _, bad := range []string{"60s,192.0.2.1,user,pass,,abc", "60s,192.0.2.1,user,pass,,SHA256:abc,extra"} {
		if _, err := ParseSSHConfig("linux", bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}
