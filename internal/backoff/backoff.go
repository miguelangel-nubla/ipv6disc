// Package backoff spaces the retries of a listener's read after an error. An error of a read isn't
// taken as passing: one that the next read returns again, as of a socket the poller gave up on,
// would otherwise spin the loop, and log a line each turn.
package backoff

import "time"

// The delay after a first error, doubled by each one that follows it up to the longest: as the
// Accept loop of net/http.
const (
	First   = 5 * time.Millisecond
	Longest = time.Second
)

// Delay is the wait after consecutive errors. Its zero value is ready, and it is of one loop: not
// for concurrent use.
type Delay struct {
	next time.Duration
}

// Next returns how long to wait after one more error in a row.
func (d *Delay) Next() time.Duration {
	if d.next == 0 {
		d.next = First
	}
	delay := d.next
	d.next = min(2*d.next, Longest)
	return delay
}

// Wait sleeps for Next. A connection closed meanwhile ends its loop at the read that follows:
// within Longest.
func (d *Delay) Wait() {
	time.Sleep(d.Next())
}

// Reset is for a read that succeeded: the next error is a first one again.
func (d *Delay) Reset() {
	d.next = 0
}
