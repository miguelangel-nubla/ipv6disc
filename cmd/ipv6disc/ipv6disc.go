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

	ipv6, ipv6Listen, ipv6Active bool
	ipv4, ipv4Listen, ipv4Active bool

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

	flag.BoolVar(&ipv6, "ipv6", true, "Discover IPv6 addresses")
	flag.BoolVar(&ipv6Listen, "ipv6-listen", true, "IPv6: listen for NDP and the discovery protocols on the interfaces")
	flag.BoolVar(&ipv6Active, "ipv6-active", true, "IPv6: probe the links, by multicast ping, SSDP and WS-Discovery")
	flag.BoolVar(&ipv4, "ipv4", false, "Discover IPv4 addresses: the plugins read their router's ARP table")
	flag.BoolVar(&ipv4Listen, "ipv4-listen", true, "IPv4: read the kernel's neighbor table")
	flag.BoolVar(&ipv4Active, "ipv4-active", true, "IPv4: sweep the local subnets, which broadcasts an ARP request for each address")
	// Before the families: the IPv6 ones.
	flag.BoolVar(&ipv6Listen, "discovery-listen", true, "Deprecated: -ipv6-listen")
	flag.BoolVar(&ipv6Active, "discovery-active", true, "Deprecated: -ipv6-active")

	flag.Var(&pluginsFlags, "plugin", "Plugin configuration: name=type:params (can be specified multiple times)")
}

func main() {
	flag.Parse()

	startUpdater()
}

func startUpdater() {
	sugar := initializeLogger()

	rediscover := lifetime / 3

	worker := ipv6disc.NewWorker(sugar, ipv6disc.Config{
		Lifetime:   lifetime,
		Rediscover: rediscover,
		IPv6:       ipv6disc.Family{Enabled: ipv6, Listen: ipv6Listen, Active: ipv6Active},
		IPv4:       ipv6disc.Family{Enabled: ipv4, Listen: ipv4Listen, Active: ipv4Active},
	})

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
