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
	logLevel   string
	lifetime   time.Duration
	rediscover time.Duration
	live       bool

	ipv6, ipv6Listen, ipv6Active bool
	ipv4, ipv4Listen, ipv4Active bool

	ipv6Lifetime, ipv4Lifetime    time.Duration
	hostnames                     bool
	hostnamesLifetime             time.Duration
	interfaces, excludeInterfaces listFlag

	pluginsFlags pluginsFlag
)

// listFlag is a comma separated list, which the flag can also be given several times for.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(value string) error {
	for _, v := range strings.Split(value, ",") {
		if v = strings.TrimSpace(v); v != "" {
			*l = append(*l, v)
		}
	}
	return nil
}

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
	defineFlags()
}

// defineFlags defines the flags on flag.CommandLine, each with its default: the tests define them
// again on a new one, as a flag set can't forget what it was given.
func defineFlags() {
	interfaces, excludeInterfaces, pluginsFlags = nil, nil, nil
	flag.StringVar(&logLevel, "log_level", "info", "The logging level: debug, info, warn, error")
	flag.DurationVar(&lifetime, "lifetime", 4*time.Hour, "How long an address stays after it was last seen")
	flag.DurationVar(&rediscover, "rediscover", 0, "How often the active discovery probes every host. Without it: a third of the shortest lifetime of the families that probe")
	flag.BoolVar(&live, "live", false, "Show the state in the terminal, updating, instead of the log")

	flag.BoolVar(&ipv6, "ipv6", true, "Discover IPv6 addresses")
	flag.BoolVar(&ipv6Listen, "ipv6_listen", true, "IPv6: listen for NDP and the discovery protocols on the interfaces")
	flag.BoolVar(&ipv6Active, "ipv6_active", true, "IPv6: probe the links, by multicast ping, SSDP and WS-Discovery")
	flag.DurationVar(&ipv6Lifetime, "ipv6_lifetime", 0, "IPv6: how long an address stays after it was last seen, in place of -lifetime")
	flag.BoolVar(&ipv4, "ipv4", false, "Discover IPv4 addresses: the plugins read their routers' ARP tables too")
	flag.BoolVar(&ipv4Listen, "ipv4_listen", true, "IPv4: read the kernel's neighbor table")
	flag.BoolVar(&ipv4Active, "ipv4_active", true, "IPv4: sweep the local subnets, which broadcasts an ARP request for each address")
	flag.DurationVar(&ipv4Lifetime, "ipv4_lifetime", 0, "IPv4: how long an address stays after it was last seen, in place of -lifetime")
	flag.BoolVar(&hostnames, "hostnames", false, "Learn the names of the hosts: listen for mDNS and ask each host its name, where the families listen, and the plugins read the names of their routers' DHCP leases")
	flag.DurationVar(&hostnamesLifetime, "hostnames_lifetime", 0, "How long a name stays after it was last said, in place of -lifetime")
	flag.Var(&interfaces, "interfaces", "The local discovery only on these interfaces, comma separated: names, or patterns as en*. Without it: all")
	flag.Var(&excludeInterfaces, "exclude_interfaces", "No local discovery on these interfaces, comma separated: names, or patterns as docker*,veth*")

	flag.Var(&pluginsFlags, "plugin", "A plugin, name=type:params, as docs/reference/plugins.md says. Given several times, several plugins")

	// The names from before, as the flags they became. Those from before the families set both.
	for old, current := range deprecatedFlags {
		var value flag.Value = flag.Lookup(current).Value
		if old == "discovery-listen" || old == "discovery-active" {
			ipv4Flag := strings.Replace(current, "ipv6", "ipv4", 1)
			value = bothValues{value, flag.Lookup(ipv4Flag).Value}
		}
		flag.Var(value, old, "Deprecated: -"+current)
	}
	flag.Usage = usage
}

// deprecatedFlags are the names flags had, and the flags they are now.
var deprecatedFlags = map[string]string{
	// These set the IPv4 ones too, as they did.
	"discovery-listen":   "ipv6_listen",
	"discovery-active":   "ipv6_active",
	"ipv6-listen":        "ipv6_listen",
	"ipv6-active":        "ipv6_active",
	"ipv6-lifetime":      "ipv6_lifetime",
	"ipv4-listen":        "ipv4_listen",
	"ipv4-active":        "ipv4_active",
	"ipv4-lifetime":      "ipv4_lifetime",
	"exclude-interfaces": "exclude_interfaces",
}

// bothValues sets two flags at once.
type bothValues [2]flag.Value

func (b bothValues) String() string { return b[0].String() }
func (b bothValues) Set(v string) error {
	if err := b[0].Set(v); err != nil {
		return err
	}
	return b[1].Set(v)
}

// IsBoolFlag lets it be given without a value, as the flags it sets.
func (b bothValues) IsBoolFlag() bool { return true }

// usage lists the flags, as flag does, without the deprecated names.
func usage() {
	listed := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	listed.SetOutput(flag.CommandLine.Output())
	flag.VisitAll(func(f *flag.Flag) {
		if _, deprecated := deprecatedFlags[f.Name]; !deprecated {
			listed.Var(f.Value, f.Name, f.Usage)
			// The default, rather than the value given: usage can come after a parse error.
			listed.Lookup(f.Name).DefValue = f.DefValue
		}
	})
	fmt.Fprintf(listed.Output(), "Usage of %s:\n", os.Args[0])
	listed.PrintDefaults()
}

// deprecatedFlagsGiven tells what to use in place of the deprecated names given.
func deprecatedFlagsGiven() []string {
	var warnings []string
	flag.Visit(func(f *flag.Flag) {
		if current, ok := deprecatedFlags[f.Name]; ok {
			if f.Name == "discovery-listen" || f.Name == "discovery-active" {
				current += " and -" + strings.Replace(current, "ipv6", "ipv4", 1)
			}
			warnings = append(warnings, fmt.Sprintf("-%s is deprecated: it is -%s", f.Name, current))
		}
	})
	return warnings
}

// unexpectedArgs is the error of the words left after the flags. There are none to give: flag
// stops at the first, so that the flags after it would be left out without a word, as -ipv4 and
// -plugin after "-ipv6 false".
func unexpectedArgs(args []string) error {
	if len(args) == 0 {
		return nil
	}
	return fmt.Errorf("unexpected argument %q: the flags take no separate words, and a boolean one is turned off as -name=false", args[0])
}

func main() {
	flag.Parse()
	if err := unexpectedArgs(flag.Args()); err != nil {
		fmt.Fprintln(flag.CommandLine.Output(), err)
		flag.Usage()
		os.Exit(2)
	}

	startUpdater()
}

func startUpdater() {
	sugar := initializeLogger()
	for _, warning := range deprecatedFlagsGiven() {
		sugar.Warn(warning)
	}

	worker := ipv6disc.NewWorker(sugar, ipv6disc.Config{
		Lifetime:   lifetime,
		Rediscover: rediscover,
		IPv6:       ipv6disc.Family{Enabled: ipv6, Listen: ipv6Listen, Active: ipv6Active, Lifetime: ipv6Lifetime},
		IPv4:       ipv6disc.Family{Enabled: ipv4, Listen: ipv4Listen, Active: ipv4Active, Lifetime: ipv4Lifetime},
		Hostnames:  ipv6disc.Hostnames{Enabled: hostnames, Lifetime: hostnamesLifetime},

		Interfaces:        interfaces,
		ExcludeInterfaces: excludeInterfaces,
	})

	// The plugins get -lifetime: a family's own, when given, is the state's to put in its place.
	for _, pCfg := range pluginsFlags {
		p, err := plugins.Create(pCfg.Type, pCfg.Name, pCfg.Params, lifetime)
		if err != nil {
			sugar.Fatalf("can't create plugin %s: %s", pCfg.Type, err)
		}
		worker.RegisterPlugin(p)
	}

	// The terminal is raw in -live, so Ctrl-C is a key there, but a signal from elsewhere, as
	// docker stop sends, has to end it too.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if live {
		// Before anything is started: without a terminal there is nothing to show it on. Not
		// by the logger, which -live silences.
		if err := terminal.Init(); err != nil {
			fmt.Fprintln(os.Stderr, "-live needs a terminal:", err)
			os.Exit(1)
		}
	}

	err := worker.Start(ctx)
	if err != nil {
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

	liveOutput := make(chan string)
	go func() {
		refresh := time.NewTicker(1 * time.Second)
		defer refresh.Stop()
		for {
			select {
			case liveOutput <- worker.State.PrettyPrint("    ", true) + worker.PrettyPrintStats("    "):
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
	terminal.Run(ctx, liveOutput)
	terminal.Close()
	stop()
	worker.Wait()
	worker.State.Close()
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
