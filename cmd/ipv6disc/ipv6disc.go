package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
	_ "github.com/miguelangel-nubla/ipv6disc/pkg/plugins/all"
	"github.com/miguelangel-nubla/ipv6disc/pkg/terminal"
)

var (
	logLevel string
	lifetime time.Duration
	live     bool

	discoveryListen bool
	discoveryActive bool
	ipv4            bool

	pluginsFlags pluginsFlag
)

type pluginsFlag []struct {
	Name   string
	Type   string
	Params string
}

func (p *pluginsFlag) String() string {
	return fmt.Sprint(*p)
}

func (p *pluginsFlag) Set(value string) error {
	var name string
	idx := strings.Index(value, "=")
	if idx == -1 {
		return fmt.Errorf("invalid plugin format, expected: name=type:params")
	}

	name = value[:idx]
	value = value[idx+1:]

	if name == "" {
		return fmt.Errorf("plugin name cannot be empty")
	}

	parts := strings.SplitN(value, ":", 2)
	if len(parts) < 2 {
		return fmt.Errorf("invalid plugin format, expected: name=type:params")
	}

	*p = append(*p, struct {
		Name   string
		Type   string
		Params string
	}{name, parts[0], parts[1]})
	return nil
}

func init() {
	flag.StringVar(&logLevel, "log_level", "info", "Logging level (debug, info, warn, error, fatal, panic) default: info")
	flag.DurationVar(&lifetime, "lifetime", 4*time.Hour, "Time to keep a discovered host entry after it has been last seen. Default: 4h")
	flag.BoolVar(&live, "live", false, "Show the current state live on the terminal, default: false")

	flag.BoolVar(&discoveryListen, "discovery-listen", true, "Enable listening for IPv6 discovery packets on interfaces")
	flag.BoolVar(&discoveryActive, "discovery-active", true, "Enable active discovery (multicast Ping, SSDP, NDP solicitation)")
	flag.BoolVar(&ipv4, "ipv4", false, "Discover IPv4 neighbors too: the plugins read their router's ARP table, and the local discovery the kernel's, after a sweep of the local subnets with active discovery")

	flag.Var(&pluginsFlags, "plugin", "Plugin configuration: name=type:params (can be specified multiple times)")
}

func main() {
	flag.Parse()

	startUpdater()
}

func startUpdater() {
	sugar := initializeLogger()

	rediscover := lifetime / 3

	worker := ipv6disc.NewWorker(sugar, rediscover, lifetime, discoveryListen, discoveryActive)
	if ipv4 {
		worker.State.EnableIPv4()
	}

	for _, pCfg := range pluginsFlags {
		p, err := plugins.Create(pCfg.Type, pCfg.Name, pCfg.Params, lifetime)
		if err != nil {
			sugar.Fatalf("can't create plugin %s: %s", pCfg.Type, err)
		}
		worker.RegisterPlugin(p)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := worker.Start(ctx)
	if err != nil {
		sugar.Fatalf("can't start worker: %s", err)
	}

	if !live {
		<-ctx.Done()
		sugar.Info("stopping")
		worker.Wait()
		return
	}

	liveOutput := make(chan string)
	go func() {
		for {
			liveOutput <- worker.State.PrettyPrint("    ", true) + worker.PrettyPrintStats("    ")
			time.Sleep(1 * time.Second)
		}
	}()
	terminal.LiveOutput(liveOutput)
}

func initializeLogger() *zap.SugaredLogger {
	zapLevel, err := getLogLevel(logLevel)
	if err != nil {
		log.Fatalf("invalid log level: %s", logLevel)
	}

	if live {
		zapLevel = zapcore.FatalLevel
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(zapLevel)
	cfg.OutputPaths = []string{"stdout"}
	cfg.ErrorOutputPaths = []string{"stderr"}
	cfg.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder

	return zap.Must(cfg.Build()).Sugar()
}

func getLogLevel(level string) (zapcore.Level, error) {
	var zapLevel zapcore.Level
	err := zapLevel.UnmarshalText([]byte(level))
	if err != nil {
		return zap.InfoLevel, err
	}
	return zapLevel, nil
}
