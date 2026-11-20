package plugins

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/internal/sshtest"
)

func TestPollerRun(t *testing.T) {
	var p Poller
	ctx, cancel := context.WithCancel(context.Background())
	runs := 0
	var errs []string
	done := make(chan error)
	go func() {
		done <- p.Run(ctx, time.Millisecond, func() (int, error) {
			runs++
			switch runs {
			case 2:
				return 0, errors.New("boom")
			case 3:
				// The shutdown, in the middle of a poll: its error is not one of the plugin.
				cancel()
				return 1, ctx.Err()
			}
			return 2, nil
		}, func(err error) { errs = append(errs, err.Error()) })
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	stats := p.Stats()
	if runs != 3 || len(errs) != 1 || errs[0] != "boom" || stats["discovery_count"] != 3 || stats["last_error"] != "boom" {
		t.Errorf("runs %d, errors %v, stats %v", runs, errs, stats)
	}

	// A run without error clears the last one.
	ctx, cancel = context.WithCancel(context.Background())
	if err := p.Run(ctx, time.Hour, func() (int, error) { cancel(); return 0, nil }, nil); err != nil || p.Stats()["last_error"] != "" {
		t.Errorf("got %v, stats %v", err, p.Stats())
	}

	// Already done: no poll.
	if err := p.Run(ctx, time.Millisecond, func() (int, error) { t.Error("a poll with its context done"); return 0, nil }, nil); err != nil {
		t.Error(err)
	}
}

// The timeout of a poll is its own, not the shutdown: it is an error of the plugin.
func TestPollerRunReportsPollTimeout(t *testing.T) {
	var p Poller
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var errs []error
	p.Run(ctx, time.Hour, func() (int, error) {
		pollCtx, pollCancel := context.WithTimeout(ctx, time.Millisecond)
		defer pollCancel()
		<-pollCtx.Done()
		return 0, pollCtx.Err()
	}, func(err error) { errs = append(errs, err); cancel() })
	if len(errs) != 1 || !errors.Is(errs[0], context.DeadlineExceeded) || p.Stats()["last_error"] == "" {
		t.Errorf("errors %v, stats %v", errs, p.Stats())
	}
}

// A plugin built by hand, without the parsers, can have no interval.
func TestPollerRunInterval(t *testing.T) {
	var p Poller
	for _, interval := range []time.Duration{0, -time.Second} {
		if err := p.Run(context.Background(), interval, func() (int, error) { t.Error("polled"); return 0, nil }, nil); err == nil {
			t.Errorf("interval %s: want an error", interval)
		}
	}
}

func TestParseSSHConfig(t *testing.T) {
	cfg, err := ParseSSHConfig("linux", "60s,192.0.2.1,user,pass,/key")
	if err != nil || cfg.Interval != time.Minute || cfg.Address != "192.0.2.1" || cfg.Username != "user" || cfg.Password != "pass" || cfg.IdentityFile != "/key" {
		t.Errorf("got %+v, %v", cfg, err)
	}
	// The spaces after the commas are not of the values, but of the password.
	cfg, err = ParseSSHConfig("linux", "60s, 192.0.2.1, user, pass, /key , SHA256:abc ")
	if err != nil || cfg.Interval != time.Minute || cfg.Address != "192.0.2.1" || cfg.Username != "user" || cfg.Password != " pass" || cfg.IdentityFile != "/key" || cfg.HostKey != "SHA256:abc" {
		t.Errorf("with spaces: got %+v, %v", cfg, err)
	}
	for _, bad := range []string{"192.0.2.1,user", "soon,192.0.2.1,user,pass", "0s,192.0.2.1,user,pass", "60s, ,user,pass", "60s,192.0.2.1, ,pass", "60s,192.0.2.1,user,, "} {
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
	_, _, err = RunSSH(context.Background(), cfg, "ip -6 neigh")
	if err == nil || !strings.Contains(err.Error(), "host key mismatch") {
		t.Errorf("pinned to another key: got %v", err)
	}
	if !errors.Is(err, ErrHostKeyMismatch) {
		t.Errorf("pinned to another key: %v is not an ErrHostKeyMismatch", err)
	}
	if got := server.Commands(); len(got) != 2 {
		t.Errorf("the host ran %v: the command must not reach a host with another key", got)
	}
	if got := server.Passwords(); got != 2 {
		t.Errorf("the host was given %d passwords, want the 2 of before: the password must not reach a host with another key", got)
	}

	cfg.HostKey = ""
	if _, _, err := RunSSH(context.Background(), cfg, "fail"); err == nil {
		t.Error("a failing command: want an error")
	}
	// A wrong password: the key the host showed is still told.
	cfg.Password = "wrong"
	if _, hostKey, err := RunSSH(context.Background(), cfg, "ip -6 neigh"); err == nil || hostKey != server.HostKey {
		t.Errorf("a wrong password: got %s, %v, want an error and the host key", hostKey, err)
	}
}

// A host with several keys shows one, the one the client prefers: here the ECDSA one. Any of its
// keys can be pinned, as ssh-keyscan lists them all.
func TestRunSSHHostWithTwoKeys(t *testing.T) {
	server := sshtest.StartTwoKeys(t, "admin", "secret", func(command string) ([]byte, error) {
		return []byte("ran " + command), nil
	})
	cfg := SSHConfig{Address: server.Address, Username: "admin", Password: "secret"}

	if _, hostKey, err := RunSSH(context.Background(), cfg, "one"); err != nil || hostKey != server.ECDSAHostKey {
		t.Errorf("unpinned: got %s, %v, want the key shown by default, %s", hostKey, err, server.ECDSAHostKey)
	}
	for _, pin := range []string{server.ECDSAHostKey, server.HostKey} {
		cfg.HostKey = pin
		// Twice: the second time with the algorithm remembered.
		for range 2 {
			if output, hostKey, err := RunSSH(context.Background(), cfg, "two"); err != nil || hostKey != pin || string(output) != "ran two" {
				t.Errorf("pinned to %s: got %q, %s, %v", pin, output, hostKey, err)
			}
		}
	}
	if remembered, ok := pinnedAlgorithms.Load(server.Address + " " + server.HostKey); !ok || len(remembered.([]string)) != 1 {
		t.Errorf("the algorithm of the Ed25519 key is not remembered: %v", remembered)
	}

	ran, passwords := len(server.Commands()), server.Passwords()
	cfg.HostKey = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	_, hostKey, err := RunSSH(context.Background(), cfg, "three")
	if !errors.Is(err, ErrHostKeyMismatch) || !strings.Contains(err.Error(), server.HostKey) || !strings.Contains(err.Error(), server.ECDSAHostKey) || hostKey != server.ECDSAHostKey {
		t.Errorf("pinned to another key: got %s, %v, want a mismatch telling both keys", hostKey, err)
	}
	if len(server.Commands()) != ran || server.Passwords() != passwords {
		t.Errorf("the command or the password reached a host with another key")
	}

	// An error past the host key, as a password refused, is not tried again with the host's other
	// keys: the password goes once, and the key told is the one pinned, which the host showed.
	for _, pin := range []string{server.ECDSAHostKey, server.HostKey} {
		// With the algorithm of the pin remembered, and without.
		for _, forget := range []bool{false, true} {
			if forget {
				pinnedAlgorithms.Delete(server.Address + " " + pin)
			}
			passwords = server.Passwords()
			_, hostKey, err := RunSSH(context.Background(), SSHConfig{Address: server.Address, Username: "admin", Password: "wrong", HostKey: pin}, "four")
			if err == nil || errors.Is(err, ErrHostKeyMismatch) || hostKey != pin || server.Passwords() != passwords+1 {
				t.Errorf("a wrong password, pinned to %s, forgotten %v: got %s, %v, and %d passwords given, want 1", pin, forget, hostKey, err, server.Passwords()-passwords)
			}
		}
	}
}

// The handshake too is bounded by the context: a host that accepts the connection and says nothing.
func TestRunSSHStopsWithItsContextInTheHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()
	for _, hostKey := range []string{"", "SHA256:abc"} {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		start := time.Now()
		_, _, err = RunSSH(ctx, SSHConfig{Address: listener.Addr().String(), Username: "admin", Password: "secret", HostKey: hostKey}, "ip neigh")
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
			t.Errorf("host key %q: got %v after %s, want the deadline of the context", hostKey, err, time.Since(start))
		}
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
