package questions

import (
	"net/netip"
	"testing"
)

// A question waits for its answer, which takes it once: an answer that isn't its own leaves it
// waiting, and one with an ID nothing asked finds none.
func TestTable(t *testing.T) {
	var table Table
	host, other := netip.MustParseAddr("192.168.1.20"), netip.MustParseAddr("192.168.1.66")
	is := func(want netip.Addr) func(netip.Addr) bool {
		return func(asked netip.Addr) bool { return asked == want }
	}
	id := table.Ask(netip.MustParseAddr("::ffff:192.168.1.20"))
	if id == 0 {
		t.Fatal("the ID zero")
	}
	if _, ok := table.Answered(id+1, is(host)); ok {
		t.Error("an answer with an ID nothing asked was taken")
	}
	if _, ok := table.Answered(id, is(other)); ok || table.Waiting() != 1 {
		t.Error("an answer of another host was taken, or took the question away")
	}
	if asked, ok := table.Answered(id, is(host)); !ok || asked != host {
		t.Errorf("the answer: %s, %v", asked, ok)
	}
	if _, ok := table.Answered(id, is(host)); ok || table.Waiting() != 0 {
		t.Error("an answer taken twice")
	}

	// Every question that waits has an ID of its own, and no more wait than Most: the oldest
	// give way, and their IDs with them.
	ids := make(map[uint16]bool)
	for range Most {
		ids[table.Ask(host)] = true
	}
	if len(ids) != Most || table.Waiting() != Most {
		t.Errorf("%d IDs for %d questions that wait, %d waiting", len(ids), Most, table.Waiting())
	}
	for range 50 {
		if id := table.Ask(host); id == 0 {
			t.Error("the ID zero")
		}
	}
	if table.Waiting() != Most {
		t.Errorf("%d waiting, want %d at most", table.Waiting(), Most)
	}
}

// A question whose time is over waits for nothing.
func TestTableTimeout(t *testing.T) {
	var table Table
	host := netip.MustParseAddr("192.168.1.20")
	id := table.Ask(host)
	q := table.waiting[id]
	q.at = q.at.Add(-Timeout - 1)
	table.waiting[id] = q
	if _, ok := table.Answered(id, func(netip.Addr) bool { return true }); ok {
		t.Error("an answer taken after its question's time was over")
	}
	table.Ask(host)
	if table.Waiting() != 1 {
		t.Errorf("%d waiting: the one whose time is over is forgotten when another is asked", table.Waiting())
	}
}
