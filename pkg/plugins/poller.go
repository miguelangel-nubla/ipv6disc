package plugins

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// PollTimeout bounds a poll: connecting, logging in and reading the neighbors.
const PollTimeout = 30 * time.Second

// Poller runs a plugin's discovery now and at every interval, and keeps the stats of the runs.
// Plugins embed it for their Stats method.
type Poller struct {
	mutex          sync.Mutex
	discoveryCount int
	lastRun        time.Time
	lastError      error
}

// Run calls discover until ctx is done, never when it already is. discover returns how many new
// addresses it found. The error of a poll that ctx being done cut short is not one of the plugin:
// it is neither given to onError nor kept for Stats.
//
// The interval must be positive, as the parsers of the params make sure: one that is not is an
// error, with no poll.
func (p *Poller) Run(ctx context.Context, interval time.Duration, discover func() (int, error), onError func(error)) error {
	if interval <= 0 {
		return fmt.Errorf("invalid interval %s: it must be positive", interval)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for ctx.Err() == nil {
		p.poll(ctx, discover, onError)
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	return nil
}

func (p *Poller) poll(ctx context.Context, discover func() (int, error), onError func(error)) {
	start := time.Now()
	found, err := discover()
	// The timeout of the poll itself is of a context of its own, so it is still reported.
	stopped := err != nil && ctx.Err() != nil

	p.mutex.Lock()
	p.lastRun = start
	p.discoveryCount += found
	if !stopped {
		p.lastError = err
	}
	p.mutex.Unlock()

	if err != nil && !stopped && onError != nil {
		onError(err)
	}
}

func (p *Poller) Stats() map[string]any {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	lastErr := ""
	if p.lastError != nil {
		lastErr = p.lastError.Error()
	}
	return map[string]any{
		"discovery_count": p.discoveryCount,
		"last_run":        p.lastRun,
		"last_error":      lastErr,
	}
}
