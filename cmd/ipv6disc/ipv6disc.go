package ipv6disc

import (
	"flag"
	"log"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/miguelangel-nubla/ipv6disc/pkg/terminal"
	"github.com/miguelangel-nubla/ipv6disc/pkg/worker"
)

var logLevel string
var ttl time.Duration
var live bool

func init() {
	flag.StringVar(&logLevel, "log_level", "info", "Logging level (debug, info, warn, error, fatal, panic) default: info")
	flag.DurationVar(&ttl, "ttl", 4*time.Hour, "Time to keep a discovered host entry in the table after it has been last seen. This is not the TTL of the DDNS record. Default: 4h")
	flag.BoolVar(&live, "live", false, "Show the currrent state live on the terminal, default: false")
}

func Start() {
	flag.Parse()

	startUpdater()
}

func startUpdater() {
	liveOutput := make(chan string)

	sugar := initializeLogger()

	table := worker.NewTable()
	err := worker.NewWorker(table, ttl, sugar).Start()
	if err != nil {
		sugar.Fatalf("can't start worker: %s", err)
	}

	go func() {
		for {
			if live {
				var result strings.Builder
				result.WriteString(table.PrettyPrint(4))
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
