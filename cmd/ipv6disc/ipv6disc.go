package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/config"
	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
	"github.com/miguelangel-nubla/ipv6disc/pkg/terminal"
)

// The flags: the rest is the configuration file's.
var (
	configFile  string
	live        bool
	showVersion bool
)

// version is the release's, which its build sets: without, the module's, when it is known.
var version string

// reference is where every key of the configuration file is told.
const reference = "https://github.com/miguelangel-nubla/ipv6disc/blob/main/docs/reference/configuration.md"

func init() {
	defineFlags()
}

// defineFlags defines the flags on flag.CommandLine, each with its default: the tests define them
// again on a new one, as a flag set can't forget what it was given.
func defineFlags() {
	flag.StringVar(&configFile, "config", "", "The configuration `file`, YAML: the families, the protocols, the names and the plugins. Without it no file is read, and the defaults discover IPv6")
	flag.BoolVar(&live, "live", false, "Show the state in the terminal, updating, instead of the log")
	flag.BoolVar(&showVersion, "version", false, "Show the version, and exit")
	flag.Usage = usage
}

// usage lists the flags as flag does, but each with two dashes, and tells where the rest is.
func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
	flag.VisitAll(func(f *flag.Flag) {
		// The kind of its value, none for a boolean, and its default when it has one.
		kind, text := flag.UnquoteUsage(f)
		line := "  --" + f.Name
		if kind != "" {
			line += " " + kind
		}
		line += "\n    \t" + text
		switch {
		case f.DefValue == "" || f.DefValue == "false":
		case kind == "string":
			line += fmt.Sprintf(" (default %q)", f.DefValue)
		default:
			line += fmt.Sprintf(" (default %s)", f.DefValue)
		}
		fmt.Fprintln(flag.CommandLine.Output(), line)
	})
	fmt.Fprintf(flag.CommandLine.Output(), "\nEverything else is in the configuration file, whose keys are at:\n  %s\n", reference)
}

// unexpectedArgs is the error of the words left after the flags. There are none to give: flag
// stops at the first, so that the flags after it would be left out without a word, as --live after
// "--version false".
func unexpectedArgs(args []string) error {
	if len(args) == 0 {
		return nil
	}
	return fmt.Errorf("unexpected argument %q: the flags take no separate words, and a boolean one is turned off as --name=false", args[0])
}

// versionString is the version of the command: the release's, or the module's as the build has
// it, of one made by go install.
func versionString() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}

func main() {
	flag.Parse()
	if err := unexpectedArgs(flag.Args()); err != nil {
		fmt.Fprintln(flag.CommandLine.Output(), err)
		flag.Usage()
		os.Exit(2)
	}
	if showVersion {
		fmt.Println("ipv6disc", versionString())
		return
	}

	startUpdater()
}

func startUpdater() {
	// Without a file, the defaults: IPv6, by the protocols that find hosts.
	file := config.Default()
	if configFile != "" {
		var err error
		if file, err = config.Load(configFile); err != nil {
			// Not by the logger, whose level the file says.
			fmt.Fprintf(os.Stderr, "ipv6disc: the configuration can't be used:\n%s\n", err)
			os.Exit(1)
		}
	}
	sugar := initializeLogger(file.LogLevel)

	worker := ipv6disc.NewWorker(sugar, file.Config())

	// The plugins get the lifetime of all: a family's own, when given, is the state's to put in
	// its place.
	plugins, err := file.NewPlugins()
	if err != nil {
		sugar.Fatalf("can't create the plugins: %s", err)
	}
	for _, p := range plugins {
		worker.RegisterPlugin(p)
	}

	// The terminal is raw in --live, so Ctrl-C is a key there, but a signal from elsewhere, as
	// docker stop sends, has to end it too.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if live {
		// Before anything is started: without a terminal there is nothing to show it on. Not
		// by the logger, which --live silences.
		if err := terminal.Init(); err != nil {
			fmt.Fprintln(os.Stderr, "--live needs a terminal:", err)
			os.Exit(1)
		}
	}

	if err := worker.Start(ctx); err != nil {
		if live {
			terminal.Close()
		}
		sugar.Fatalf("can't start worker: %s", err)
	}

	if !live {
		<-ctx.Done()
		sugar.Info("stopping")
		worker.Wait()
		worker.State.Close()
		return
	}

	liveOutput := make(chan pretty.Page)
	go func() {
		refresh := time.NewTicker(1 * time.Second)
		defer refresh.Stop()
		for {
			select {
			case liveOutput <- append(worker.State.Page("    "), worker.StatsPage("    ")...):
			case <-ctx.Done():
				return
			}
			select {
			case <-refresh.C:
			case <-ctx.Done():
				return
			}
		}
	}()
	terminal.RunPages(ctx, liveOutput)
	terminal.Close()
	stop()
	worker.Wait()
	worker.State.Close()
}

func initializeLogger(level string) *zap.SugaredLogger {
	zapLevel, err := getLogLevel(level)
	if err != nil {
		log.Fatalf("invalid log level: %s", level)
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
