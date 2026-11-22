// Package questions keeps the questions a protocol sent to a host and still waits the answer of,
// by their ID: an answer is taken only as the answer to one of them.
package questions

import (
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"
)

const (
	// Timeout is how long the answer to a question is waited for: one that comes later answers
	// nothing, and is left.
	Timeout = 5 * time.Second
	// Most is how many wait at once: the oldest gives way to one more.
	Most = 1024
)

// Table is the questions that wait. Its zero value is ready.
type Table struct {
	mutex   sync.Mutex
	waiting map[uint16]question
}

type question struct {
	addr netip.Addr
	at   time.Time
}

// Ask returns the ID of a question to the host at addr, which waits for its answer: one no
// question waiting has, and not zero.
func (t *Table) Ask(addr netip.Addr) uint16 {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	now := time.Now()
	if t.waiting == nil {
		t.waiting = make(map[uint16]question)
	}
	var oldest uint16
	for id, q := range t.waiting {
		if now.Sub(q.at) > Timeout {
			delete(t.waiting, id)
		} else if o, ok := t.waiting[oldest]; !ok || q.at.Before(o.at) {
			oldest = id
		}
	}
	if len(t.waiting) >= Most {
		delete(t.waiting, oldest)
	}
	for {
		id := uint16(rand.Uint32())
		if _, taken := t.waiting[id]; id != 0 && !taken {
			t.waiting[id] = question{addr.Unmap().WithZone(""), now}
			return id
		}
	}
}

// Answered tells the address the question with that ID was sent to, if it still waits and is
// tells the answer is its own: once, as a host answers once. An answer that isn't, as one from
// another address, leaves the question waiting for the one that is.
func (t *Table) Answered(id uint16, is func(asked netip.Addr) bool) (netip.Addr, bool) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	q, ok := t.waiting[id]
	if !ok || time.Since(q.at) > Timeout || !is(q.addr) {
		return netip.Addr{}, false
	}
	delete(t.waiting, id)
	return q.addr, true
}

// Waiting is how many questions wait, those whose time is over too until one more is asked.
func (t *Table) Waiting() int {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return len(t.waiting)
}
