package ipv6disc

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

type blockingPlugin struct{ stopped chan struct{} }

func (p *blockingPlugin) Name() string          { return "blocking" }
func (p *blockingPlugin) Stats() map[string]any { return nil }
func (p *blockingPlugin) Start(ctx context.Context, _ *State, _ func(error)) error {
	<-ctx.Done()
	close(p.stopped)
	return nil
}

func TestWorkerStopsWithItsContext(t *testing.T) {
	w := NewWorker(zap.NewNop().Sugar(), time.Minute, time.Hour, false, false)
	plugin := &blockingPlugin{stopped: make(chan struct{})}
	w.RegisterPlugin(plugin)

	ctx, cancel := context.WithCancel(context.Background())
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()

	done := make(chan struct{})
	go func() { w.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after the context was done")
	}
	select {
	case <-plugin.stopped:
	default:
		t.Error("Wait returned before the plugin stopped")
	}
}

func TestWorkerWithNothingToDo(t *testing.T) {
	w := NewWorker(zap.NewNop().Sugar(), time.Minute, time.Hour, false, false)
	if err := w.Start(context.Background()); err == nil {
		t.Error("no plugins and no listening: want an error")
	}
}
