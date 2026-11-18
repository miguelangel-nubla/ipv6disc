package plugins

import (
	"context"
	"sync"
	"time"
)

// Poller runs a plugin's discovery now and at every interval, and keeps the stats of the runs.
// Plugins embed it for their Stats method.
type Poller struct {
	mutex          sync.Mutex
	discoveryCount int
	lastRun        time.Time
	lastError      error
}

// Run calls discover until ctx is done. discover returns how many new addresses it found.
func (p *Poller) Run(ctx context.Context, interval time.Duration, discover func() (int, error), onError func(error)) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		p.poll(discover, onError)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (p *Poller) poll(discover func() (int, error), onError func(error)) {
	start := time.Now()
	found, err := discover()

	p.mutex.Lock()
	p.lastRun = start
	p.discoveryCount += found
	p.lastError = err
	p.mutex.Unlock()

	if err != nil && onError != nil {
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
