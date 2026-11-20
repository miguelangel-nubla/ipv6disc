package ipv6disc_test

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
	_ "github.com/miguelangel-nubla/ipv6disc/pkg/plugins/all"
	"go.uber.org/zap"
)

// The worker, a plugin, and the state's changes. docs/library.md shows this body.
func Example() {
	ctx, logger := context.Background(), zap.NewNop().Sugar()
	run := func() error {
		config := ipv6disc.DefaultConfig() // IPv6 by every way, no IPv4
		config.IPv4 = ipv6disc.Family{Enabled: true, Listen: true}
		config.ExcludeInterfaces = []string{"docker*", "veth*"}

		worker := ipv6disc.NewWorker(logger, config)

		plugin, err := plugins.Create("mikrotik", "router", "interval=60s,address=192.168.88.1,username=ipv6disc,password=secret", config.Lifetime)
		if err != nil {
			return err
		}
		worker.RegisterPlugin(plugin)

		// Before Start, not to miss the first changes.
		changes, cancel := worker.State.Subscribe()
		defer cancel()

		if err := worker.Start(ctx); err != nil { // until ctx is done
			return err
		}
		defer worker.State.Close() // after Wait: the addresses stop expiring
		defer worker.Wait()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-changes:
				for mac, addrs := range worker.State.GetAll() {
					fmt.Println(mac, addrs.FilterValid().Strings())
				}
			}
		}
	}
	_ = run
}

// The page shows the example's body: the code there compiles.
func TestLibraryPageShowsTheExample(t *testing.T) {
	page, err := os.ReadFile("docs/library.md")
	if err != nil {
		t.Fatal(err)
	}
	shown := regexp.MustCompile("(?s)```go\n(.*?)```").FindSubmatch(page)
	source, err := os.ReadFile("example_test.go")
	if err != nil {
		t.Fatal(err)
	}
	body := regexp.MustCompile(`(?s)run := func\(\) error \{\n(.*?)\n\t\}\n\t_ = run`).FindSubmatch(source)
	if shown == nil || body == nil {
		t.Fatal("no code to compare")
	}
	var lines []string
	for _, l := range strings.Split(string(body[1]), "\n") {
		lines = append(lines, strings.TrimPrefix(l, "\t\t"))
	}
	if want := strings.Join(lines, "\n") + "\n"; string(shown[1]) != want {
		t.Errorf("docs/library.md shows other code than Example:\n%s", want)
	}
}
