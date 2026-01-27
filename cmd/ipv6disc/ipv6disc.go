package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
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
	flag.BoolVar(&live, "live", false, "Show the currrent state live on the terminal, default: false")

	flag.BoolVar(&discoveryListen, "discovery-listen", true, "Enable listening for IPv6 discovery packets on interfaces")
	flag.BoolVar(&discoveryActive, "discovery-active", true, "Enable active discovery (multicast Ping, SSDP, NDP solicitation)")

	flag.Var(&pluginsFlags, "plugin", "Plugin configuration: name=type:params (can be specified multiple times)")
}

func main() {
	flag.Parse()

	startUpdater()
}

func startUpdater() {
	liveOutput := make(chan string)

	sugar := initializeLogger()

	rediscover := lifetime / 3

	worker := ipv6disc.NewWorker(sugar, rediscover, lifetime, discoveryListen, discoveryActive)

	for _, pCfg := range pluginsFlags {
		p, err := plugins.Create(pCfg.Type, pCfg.Name, pCfg.Params, lifetime)
		if err != nil {
			sugar.Fatalf("can't create plugin %s: %s", pCfg.Type, err)
		}
		worker.RegisterPlugin(p)
	}

	err := worker.Start()
	if err != nil {
		sugar.Fatalf("can't start worker: %s", err)
	}

	go func() {
		for {
			if live {
				var result strings.Builder
				result.WriteString(worker.State.PrettyPrint("    ", true))
				result.WriteString(worker.PrettyPrintStats("    "))
				liveOutput <- result.String()
			}

			time.Sleep(1 * time.Second)
		}
	}()

	if live {
		terminal.LiveOutput(liveOutput)
	} else {
		select {}
	}
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

	logger := zap.Must(cfg.Build())
	defer logger.Sync()

	return logger.Sugar()
}

func getLogLevel(level string) (zapcore.Level, error) {
	var zapLevel zapcore.Level
	err := zapLevel.UnmarshalText([]byte(level))
	if err != nil {
		return zap.InfoLevel, err
	}
	return zapLevel, nil
}
