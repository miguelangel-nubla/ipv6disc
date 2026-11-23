//go:build darwin

package ipv6disc

import (
	"context"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// The flags the kernel is asked for are those ifconfig tells of the same addresses: on a machine
// with temporary addresses, as a Mac on a network with IPv6 is, and with the deprecated ones it
// keeps of those it replaced. Without any, there is nothing to tell apart, and it says so.
func TestAddrFlagsAreIfconfigs(t *testing.T) {
	out, err := exec.Command("ifconfig").Output()
	if err != nil {
		t.Skipf("ifconfig: %v", err)
	}
	temporary, deprecated := make(map[netip.Addr]bool), make(map[netip.Addr]bool)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "inet6" {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil || addr.Zone() != "" || addr.IsLinkLocalUnicast() || addr.IsLoopback() {
			continue
		}
		for _, word := range fields[2:] {
			switch word {
			case "temporary":
				temporary[addr] = true
			case "deprecated":
				deprecated[addr] = true
			}
		}
	}
	t.Logf("ifconfig: %d temporary, %d deprecated", len(temporary), len(deprecated))

	gotTemporary, gotDeprecated := temporaryAddrs(), unlistenableAddrs()
	for addr := range temporary {
		if !gotTemporary[addr] {
			t.Errorf("%s is temporary to ifconfig, and not to the worker", addr)
		}
	}
	for addr := range gotTemporary {
		if !temporary[addr] {
			t.Errorf("%s is temporary to the worker, and not to ifconfig", addr)
		}
	}
	for addr := range deprecated {
		if !gotDeprecated[addr] {
			t.Errorf("%s is deprecated to ifconfig, and not to the worker", addr)
		}
	}
	for addr := range gotDeprecated {
		if !deprecated[addr] {
			t.Errorf("%s is deprecated to the worker, and not to ifconfig", addr)
		}
	}
}

// The worker starts on none of the deprecated addresses: macOS doesn't let them be listened on,
// and each would fail at every reading of the interfaces. What it starts on is told by its log,
// whether it could listen or, without the privilege, not.
func TestDeprecatedAddressesAreNotListenedOn(t *testing.T) {
	deprecated := unlistenableAddrs()
	if len(deprecated) == 0 {
		t.Skip("this machine has no deprecated address")
	}
	core, logs := observer.New(zap.DebugLevel)
	w := NewWorker(zap.New(core).Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, IPv6: Family{Enabled: true, Listen: true}})
	ctx, cancel := context.WithCancel(context.Background())
	w.checkInterfaces(ctx)
	time.Sleep(500 * time.Millisecond)
	cancel()
	w.Wait()
	w.State.Close()

	started := 0
	for _, entry := range logs.All() {
		if !strings.HasPrefix(entry.Message, "starting discovery on ") {
			continue
		}
		started++
		for addr := range deprecated {
			if strings.HasSuffix(entry.Message, " "+addr.String()) {
				t.Errorf("the worker started on %s, which is deprecated", addr)
			}
		}
	}
	if started == 0 {
		t.Error("the worker started on no address: the test tells nothing")
	}
}
