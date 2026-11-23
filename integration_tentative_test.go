//go:build linux && integration

package ipv6disc

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// An address the kernel still checks for a duplicate is among the interface's, but can't be
// listened on yet: as the one of a prefix just announced, or any at boot, when the worker starts
// before the check ends. Here it is the only one the interface has, as at boot. The worker
// listens on it seconds after it can, not at the reading of the interfaces a minute later, finds
// the hosts by it, and tells no error: nothing is wrong.
func TestLiveAddressStillChecked(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runInNamespace(t, "TestLiveAddressStillChecked")
		return
	}
	late, peerLate := netip.MustParseAddr("fd00:6:9::1"), netip.MustParseAddr("fd00:6:9::2")
	iface, err := net.InterfaceByName("veth-worker")
	if err != nil {
		t.Fatal(err)
	}
	// Three solicitations for it, a second apart: checked for three seconds, and more.
	if out, err := exec.Command("sysctl", "-qw", "net.ipv6.conf.veth-worker.dad_transmits=3").CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	ip(t, "addr", "del", workerAddr.String()+"/64", "dev", "veth-worker")
	ip(t, "-n", peerNamespace, "addr", "add", peerLate.String()+"/64", "dev", "veth-peer", "nodad")
	ip(t, "addr", "add", late.String()+"/64", "dev", "veth-worker")
	if out, _ := exec.Command("ip", "-6", "-o", "addr", "show", "dev", "veth-worker", "tentative").CombinedOutput(); !strings.Contains(string(out), late.String()) {
		t.Fatalf("%s is not being checked for a duplicate: the test's premise is gone\n%s", late, out)
	}

	core, logs := observer.New(zap.DebugLevel)
	w := NewWorker(zap.New(core).Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Minute, Rediscover: 2 * time.Second,
		IPv6: Family{Enabled: true, Listen: true, Active: true}})
	ctx, cancel := context.WithCancel(context.Background())
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		w.Wait()
		w.State.Close()
		if t.Failed() {
			for _, entry := range logs.All() {
				t.Logf("%s %s %v", entry.Level, entry.Message, entry.ContextMap())
			}
		}
	}()

	// Once it is checked it is listened on: this machine's, as each the worker listens on, and
	// the peer is found by it.
	started := time.Now()
	waitFor(t, 20*time.Second, "the worker on the address, once it is checked", func() bool { return has(w, iface.HardwareAddr.String(), late) })
	t.Logf("listening on %s %s after the worker started", late, time.Since(started).Round(100*time.Millisecond))
	waitFor(t, 20*time.Second, "the peer's address", func() bool { return has(w, peerMAC, peerLate) })
	for _, entry := range logs.FilterLevelExact(zapcore.ErrorLevel).All() {
		t.Errorf("an error, of an address that is only not there yet: %s %v", entry.Message, entry.ContextMap())
	}
}
