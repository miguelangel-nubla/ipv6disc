package ipv6disc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/pkg/ndp"
	"github.com/miguelangel-nubla/ipv6disc/pkg/ping"
	"github.com/miguelangel-nubla/ipv6disc/pkg/ssdp"
	"github.com/miguelangel-nubla/ipv6disc/pkg/wsd"
	"go.uber.org/zap"
)

type InvalidInterfaceError struct {
	iface *net.Interface
}

func (e *InvalidInterfaceError) Error() string {
	return fmt.Sprintf("invalid interface: %s", e.iface.Name)
}

type Worker struct {
	*State
	logger        *zap.SugaredLogger
	plugins       []Plugin
	protocolConns map[string]*InterfaceProcesses
	workerCancels map[string]context.CancelFunc
	pcMutex       sync.RWMutex
	// The goroutines Start starts, for Wait.
	running sync.WaitGroup

	config Config
}

type worker interface {
	Stats() map[string]any
}

type DiscoveryProtocol struct {
	Name   string
	Worker worker
}

type InterfaceProcesses struct {
	InterfaceName string
	Address       netip.Addr
	Protocols     []*DiscoveryProtocol
}

// NewWorker makes a worker that discovers addresses as config says; Start runs it.
func NewWorker(logger *zap.SugaredLogger, config Config) *Worker {
	s := NewState()
	s.SetLogger(logger)
	s.SetFamilies(config.IPv6.Enabled, config.IPv4.Enabled)
	// The families' own lifetimes, as given: without, each registration's.
	s.SetLifetimes(config.IPv6.Lifetime, config.IPv4.Lifetime)
	config = config.withDefaults()

	return &Worker{
		State:         s,
		logger:        logger,
		config:        config,
		plugins:       make([]Plugin, 0),
		protocolConns: make(map[string]*InterfaceProcesses),
		workerCancels: make(map[string]context.CancelFunc),
	}
}

func (w *Worker) RegisterPlugin(p Plugin) {
	w.logger.Infof("registering plugin: %s", p.Name())
	w.plugins = append(w.plugins, p)
}

func (w *Worker) PrettyPrintStats(prefix string) string {
	var result strings.Builder

	result.WriteString(prefix + "Protocol Workers:\n")
	w.pcMutex.RLock()
	// Group by interface
	ifaceMap := make(map[string][]*InterfaceProcesses)
	for _, ip := range w.protocolConns {
		ifaceMap[ip.InterfaceName] = append(ifaceMap[ip.InterfaceName], ip)
	}
	w.pcMutex.RUnlock()

	// Sort interface names
	ifaceNames := make([]string, 0, len(ifaceMap))
	for name := range ifaceMap {
		ifaceNames = append(ifaceNames, name)
	}
	sort.Strings(ifaceNames)

	for _, name := range ifaceNames {
		fmt.Fprintf(&result, "%s    %s:\n", prefix, name)
		ips := ifaceMap[name]
		// Sort by IP within interface
		sort.Slice(ips, func(i, j int) bool {
			return ips[i].Address.String() < ips[j].Address.String()
		})

		for _, ip := range ips {
			fmt.Fprintf(&result, "%s        %s:\n", prefix, ip.Address.String())

			for _, p := range ip.Protocols {
				stats := p.Worker.Stats()
				fmt.Fprintf(&result, "%s            %-5s:", prefix, p.Name)
				// Sort keys for consistent output
				sKeys := make([]string, 0, len(stats))
				for sk := range stats {
					sKeys = append(sKeys, sk)
				}
				sort.Strings(sKeys)
				for _, sk := range sKeys {
					fmt.Fprintf(&result, " %s=%v", sk, stats[sk])
				}
				result.WriteString("\n")
			}
		}
	}

	result.WriteString(prefix + "Plugins:\n")
	for _, p := range w.plugins {
		stats := p.Stats()
		fmt.Fprintf(&result, "%s    %s:", prefix, p.Name())
		// Sort keys for consistent output
		sKeys := make([]string, 0, len(stats))
		for k := range stats {
			sKeys = append(sKeys, k)
		}
		sort.Strings(sKeys)
		for _, k := range sKeys {
			v := stats[k]
			if t, ok := v.(time.Time); ok {
				fmt.Fprintf(&result, " %s=%s", k, t.Format("15:04:05"))
			} else {
				fmt.Fprintf(&result, " %s=%v", k, v)
			}
		}
		result.WriteString("\n")
	}

	return result.String()
}

// Start runs the plugins and, when listening is enabled, the discovery on every interface address,
// which it keeps in step with the addresses the system has.
// The discovery stops when ctx is done: Wait waits for it to.
func (w *Worker) Start(ctx context.Context) error {
	if err := w.config.validate(); err != nil {
		return err
	}
	if len(w.plugins) == 0 && !w.config.listensIPv6() && !w.config.listensIPv4() {
		return fmt.Errorf("no plugins configured and no local discovery: nothing to do")
	}

	for _, p := range w.plugins {
		w.running.Add(1)
		go func() {
			defer w.running.Done()
			err := p.Start(ctx, w.State, func(err error) {
				w.logger.Errorf("plugin %s error: %s", p.Name(), err)
			})
			if err != nil {
				w.logger.Errorf("plugin %s failed to start: %s", p.Name(), err)
			}
		}()
	}

	if w.config.listensIPv6() {
		w.running.Add(1)
		go func() {
			defer w.running.Done()
			ticker := time.NewTicker(interfaceCheckInterval)
			defer ticker.Stop()

			for {
				w.checkInterfaces(ctx)
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}

	if w.config.listensIPv4() {
		w.running.Add(1)
		go func() {
			defer w.running.Done()
			w.discoverIPv4(ctx)
		}()
	}

	return nil
}

// Wait returns once the discovery stopped, after the context of Start is done: the listeners are
// closed, and the plugins returned.
func (w *Worker) Wait() {
	w.running.Wait()
}

// interfaceCheckInterval is how often the worker looks for interface addresses that came or went.
const interfaceCheckInterval = time.Minute

// Prefixes returns the /64 networks of the addresses being listened on.
func (w *Worker) Prefixes() []netip.Prefix {
	w.pcMutex.RLock()
	defer w.pcMutex.RUnlock()

	seen := make(map[netip.Prefix]bool)
	var result []netip.Prefix
	for _, processes := range w.protocolConns {
		prefix := netip.PrefixFrom(processes.Address, 64).Masked()
		if !seen[prefix] {
			seen[prefix] = true
			result = append(result, prefix)
		}
	}
	return result
}

// Solicit sends a neighbor solicitation for target on the links that have its /64. If the address
// is there, its answer registers it as any other discovered address. It returns how many links it
// was sent on: an address that stays quiet is otherwise never found.
func (w *Worker) Solicit(target netip.Addr) (int, error) {
	w.pcMutex.RLock()
	defer w.pcMutex.RUnlock()

	sent := 0
	interfaces := make(map[string]bool)
	var errs []error
	for _, processes := range w.protocolConns {
		if interfaces[processes.InterfaceName] || !netip.PrefixFrom(processes.Address, 64).Masked().Contains(target) {
			continue
		}
		for _, protocol := range processes.Protocols {
			conn, ok := protocol.Worker.(*ndp.Conn)
			if !ok {
				continue
			}
			if err := conn.SendNeighborSolicitation(&target); err != nil {
				errs = append(errs, err)
				continue
			}
			interfaces[processes.InterfaceName] = true
			sent++
		}
	}
	return sent, errors.Join(errs...)
}

func (w *Worker) checkInterfaces(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		w.logger.Errorf("error getting interfaces: %s", err)
		return
	}

	// The addresses still there: the workers of the others are stopped.
	seenAddrs := make(map[string]bool)

	for _, iface := range ifaces {
		if err := isValidInterface(&iface); err != nil || !w.config.usesInterface(iface.Name) {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			w.logger.Errorf("error getting IPv6 addresses for interface %s: %s", iface.Name, err)
			continue
		}

		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipNet.IP)
			addr = addr.Unmap()
			if !ok || addr.Is4() || addr.IsLinkLocalUnicast() {
				continue
			}

			addrStr := addr.String()
			seenAddrs[addrStr] = true

			w.pcMutex.Lock()
			_, running := w.workerCancels[addrStr]
			if !running {
				ctx, cancel := context.WithCancel(ctx)
				w.workerCancels[addrStr] = cancel
				w.logger.Debugf("starting discovery on %s %s", iface.Name, addrStr)
				w.running.Add(1)
				go func() {
					defer w.running.Done()
					w.StartInterfaceAddr(ctx, iface, addr)
					// It also ends on a failure to listen: let the next check try again, unless a
					// new worker took its place already.
					w.pcMutex.Lock()
					if ctx.Err() == nil {
						delete(w.workerCancels, addrStr)
					}
					w.pcMutex.Unlock()
					cancel()
				}()
			}
			w.pcMutex.Unlock()
		}
	}

	w.pcMutex.Lock()
	for addrStr, cancel := range w.workerCancels {
		if !seenAddrs[addrStr] {
			w.logger.Infof("stopping discovery on %s", addrStr)
			cancel()
			delete(w.workerCancels, addrStr)
		}
	}
	w.pcMutex.Unlock()
}

func (w *Worker) StartInterfaceAddr(ctx context.Context, iface net.Interface, addr netip.Addr) {
	var err error
	var ndpConn *ndp.Conn
	var pingConn *ping.Conn
	var ssdpConn *ssdp.Conn
	var wsdConn *wsd.Conn
	// For the expiration events, which can come before it listens and after it stops.
	var pinger atomic.Pointer[ping.Conn]

	// Ping an address before it expires: its answer keeps it. The state logs the expiration.
	addrOnExpiration := func(expiredAddr *Addr, remainingEvents AddrExpirationRemainingEvents) {
		if remainingEvents == 0 {
			return
		}

		w.logger.Debugw("host not seen for a while, pinging",
			zap.String("ipv6", netip.AddrFrom16(expiredAddr.As16()).String()),
			zap.String("mac", expiredAddr.Hw.String()),
			zap.String("iface", iface.Name),
			zap.Int("remainingEvents", int(remainingEvents)),
		)

		if pingConn := pinger.Load(); pingConn != nil {
			err := pingConn.SendPing(&expiredAddr.Addr)
			if err != nil {
				w.logger.Errorw("ping failed",
					zap.String("ipv6", netip.AddrFrom16(expiredAddr.As16()).String()),
					zap.String("mac", expiredAddr.Hw.String()),
					zap.String("iface", iface.Name),
					zap.Error(err),
				)
			}
		}
	}

	processNDP := func(receivedAddr netip.Addr, receivedNetHardwareAddr net.HardwareAddr) bool {
		_, existing := w.State.registerLocal(receivedNetHardwareAddr, receivedAddr, iface.Name, w.config.Lifetime, addrOnExpiration)
		return !existing
	}

	// The errors of a protocol, and the failure to listen for it, which ends the worker.
	onError := func(protocol string) func(error) {
		return func(err error) {
			w.logger.Errorw(protocol+" error",
				zap.String("interface", iface.Name),
				zap.String("address", addr.String()),
				zap.Error(err),
			)
		}
	}
	listenFailed := func(protocol string, err error) {
		w.logger.Errorw("error listening for "+protocol,
			zap.String("interface", iface.Name),
			zap.String("address", addr.String()),
			zap.Error(err),
		)
	}

	ndpConn, err = ndp.ListenForNDP(&iface, addr, processNDP, onError("NDP"))
	if err != nil {
		listenFailed("NDP", err)
		return
	}
	defer ndpConn.Close()

	// The other protocols only tell an address: a neighbor solicitation asks its MAC.
	pingConn, err = ping.ListenForICMP(&iface, addr, onFoundAddrFunc(ndpConn, &iface, w.logger, "ICMP echo response"), onError("ICMP"))
	if err != nil {
		listenFailed("ICMP", err)
		return
	}
	defer pingConn.Close()
	pinger.Store(pingConn)
	defer pinger.Store(nil)

	ssdpConn, err = ssdp.ListenForSSDP(&iface, addr, onFoundAddrFunc(ndpConn, &iface, w.logger, "SSDP announcement"), onError("SSDP"))
	if err != nil {
		listenFailed("SSDP", err)
		return
	}
	defer ssdpConn.Close()

	wsdConn, err = wsd.ListenForWSD(&iface, addr, onFoundAddrFunc(ndpConn, &iface, w.logger, "WSD message"), onError("WSD"))
	if err != nil {
		listenFailed("WSD", err)
		return
	}
	defer wsdConn.Close()

	processes := &InterfaceProcesses{
		InterfaceName: iface.Name,
		Address:       addr,
		Protocols: []*DiscoveryProtocol{
			{Name: "ndp", Worker: ndpConn},
			{Name: "ping", Worker: pingConn},
			{Name: "ssdp", Worker: ssdpConn},
			{Name: "wsd", Worker: wsdConn},
		},
	}
	w.pcMutex.Lock()
	w.protocolConns[addr.String()] = processes
	w.pcMutex.Unlock()
	defer func() {
		w.pcMutex.Lock()
		// Unless a new worker for the same address replaced it already.
		if w.protocolConns[addr.String()] == processes {
			delete(w.protocolConns, addr.String())
		}
		w.pcMutex.Unlock()
	}()

	discover := func() {
		w.State.RegisterSelf(iface.HardwareAddr, addr, iface.Name, temporaryAddrs()[addr], w.config.Lifetime, addrOnExpiration)

		if !w.config.probesIPv6() {
			return
		}

		w.logger.Infof("active discovery started on %s %s", iface.Name, addr.String())
		startMulticast("PING", pingConn.DiscoverMulticast, pingConn.GetListenAddr().String(), w.logger)
		startMulticast("SSDP", ssdpConn.DiscoverMulticast, ssdpConn.GetListenAddrPort().String(), w.logger)
		startMulticast("WSD", wsdConn.DiscoverMulticast, wsdConn.GetListenAddrPort().String(), w.logger)
	}

	// Bootstrap discovery
	discover()

	// Periodic re-discovery
	ticker := time.NewTicker(w.config.Rediscover)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			discover()
		}
	}
}

func isValidInterface(iface *net.Interface) error {
	if iface.Flags&net.FlagUp != 0 &&
		iface.Flags&net.FlagMulticast != 0 &&
		iface.Flags&net.FlagLoopback == 0 {
		return nil
	}
	return &InvalidInterfaceError{iface}
}

// onFoundAddrFunc returns the callback for the addresses a protocol hears from: it asks their MAC,
// as only NDP tells it, and ignores the interface's own addresses.
func onFoundAddrFunc(ndpConn *ndp.Conn, iface *net.Interface, logger *zap.SugaredLogger, logString string) func(remoteIP netip.Addr) bool {
	return func(remoteIP netip.Addr) bool {
		if addrs, err := iface.Addrs(); err == nil {
			for _, a := range addrs {
				if ipNet, ok := a.(*net.IPNet); ok {
					if addr, ok := netip.AddrFromSlice(ipNet.IP); ok && addr.Unmap() == remoteIP.WithZone("") {
						return false
					}
				}
			}
		}

		logger.Debugw(logString+" received",
			zap.String("remote", remoteIP.String()),
			zap.String("interface", iface.Name),
		)
		if err := ndpConn.SendNeighborSolicitation(&remoteIP); err != nil {
			logger.Debugw("neighbor solicitation failed",
				zap.String("remote", remoteIP.String()),
				zap.String("interface", iface.Name),
				zap.Error(err),
			)
		}
		return true
	}
}

// startMulticast runs a protocol's multicast discovery. A failure, as when the interface goes away,
// is only logged: the next run tries again.
func startMulticast(protocol string, discover func() error, listener string, logger *zap.SugaredLogger) {
	logger.Debugw(protocol+" discover multicast", zap.String("listener", listener))

	if err := discover(); err != nil {
		logger.Errorw(protocol+" discover multicast failed",
			zap.String("listener", listener),
			zap.Error(err),
		)
	}
}
