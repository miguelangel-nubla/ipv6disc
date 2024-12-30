package main

import (
	"flag"
	"log"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/terminal"
)

var logLevel string
var lifetime time.Duration
var live bool

func init() {
	flag.StringVar(&logLevel, "log_level", "info", "Logging level (debug, info, warn, error, fatal, panic) default: info")
	flag.DurationVar(&lifetime, "lifetime", 4*time.Hour, "Time to keep a discovered host entry after it has been last seen. Default: 4h")
	flag.BoolVar(&live, "live", false, "Show the currrent state live on the terminal, default: false")
}

func main() {
	flag.Parse()

	startUpdater()
}

func startUpdater() {
	liveOutput := make(chan string)

	sugar := initializeLogger()

	rediscover := lifetime / 3

	worker := ipv6disc.NewWorker(sugar, rediscover, lifetime)

	err := worker.Start()
	if err != nil {
		sugar.Fatalf("can't start worker: %s", err)
	}

	go func() {
		for {
			if live {
				var result strings.Builder
				result.WriteString(worker.State.PrettyPrint("    "))
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
