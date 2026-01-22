package ipv6disc

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"sort"
	"strings"

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
	rediscover    time.Duration
	lifetime      time.Duration
	plugins       []Plugin
	protocolConns map[string]*InterfaceProcesses
	workerCancels map[string]context.CancelFunc
	pcMutex       sync.RWMutex

	discoveryListen bool
	discoveryActive bool
}

type worker interface {
	Stats() map[string]any
}

type DiscoveryProtocol struct {
	Name   string
	Worker worker
}

type HostCounter interface {
	IncrementHostsFound()
}

type InterfaceProcesses struct {
	InterfaceName string
	Address       netip.Addr
	Protocols     []*DiscoveryProtocol
}

func NewWorker(logger *zap.SugaredLogger, rediscover time.Duration, lifetime time.Duration, discoveryListen bool, discoveryActive bool) *Worker {
	s := NewState()
	s.SetLogger(logger)

	return &Worker{
		State:           s,
		logger:          logger,
		rediscover:      rediscover,
		lifetime:        lifetime,
		plugins:         make([]Plugin, 0),
		protocolConns:   make(map[string]*InterfaceProcesses),
		workerCancels:   make(map[string]context.CancelFunc),
		discoveryListen: discoveryListen,
		discoveryActive: discoveryActive,
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

func (w *Worker) Start() error {
	if len(w.plugins) > 0 {
		go func() {
			for {
				for _, p := range w.plugins {
					err := p.Discover(w.State)
					if err != nil {
						w.logger.Errorf("plugin %s discovery failed: %s", p.Name(), err)
					}
				}
				time.Sleep(w.rediscover)
			}
		}()
	}

	go func() {
		ticker := time.NewTicker(time.Minute * 1)
		defer ticker.Stop()

		for {
			if w.discoveryListen {
				w.checkInterfaces()
			}
			<-ticker.C
		}
	}()

	if len(w.plugins) > 0 {
		return nil
	}

	return nil
}

func (w *Worker) checkInterfaces() {
	ifaces, err := net.Interfaces()
	if err != nil {
		w.logger.Errorf("error getting interfaces: %s", err)
		return
	}

	// Track seen addresses to identify removed ones
	seenAddrs := make(map[string]bool)

	for _, iface := range ifaces {
		err := isValidInterface(&iface)
		if err != nil {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			w.logger.Errorf("error getting IPv6 addresses for interface %s: %s", iface.Name, err)
			continue
		}

		for _, a := range addrs {
			addr := netip.MustParseAddr(a.(*net.IPNet).IP.String())
			if !addr.Is4() && !addr.IsLinkLocalUnicast() {
				addrStr := addr.String()
				seenAddrs[addrStr] = true

				w.pcMutex.RLock()
				_, exists := w.protocolConns[addrStr]
				w.pcMutex.RUnlock()

				if !exists {
					w.logger.Debugf("starting discovery on %s %s", iface.Name, addrStr)
					ctx, cancel := context.WithCancel(context.Background())

					w.pcMutex.Lock()
					w.workerCancels[addrStr] = cancel
					w.pcMutex.Unlock()

					go func(iface net.Interface, addr netip.Addr) {
						w.StartInterfaceAddr(ctx, iface, addr)
						w.pcMutex.Lock()
						delete(w.workerCancels, addr.String())
						w.pcMutex.Unlock()
					}(iface, addr)
				}
			}
		}
	}

	// Stop workers for addresses that are gone
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

	addrOnExpiration := func(expiredAddr *Addr, remainingEvents AddrExpirationRemainingEvents) {
		if remainingEvents == 0 {
			w.logger.Infow("host expired",
				zap.String("ipv6", netip.AddrFrom16(expiredAddr.As16()).String()),
				zap.String("mac", expiredAddr.Hw.String()),
				zap.String("iface", iface.Name),
			)
			return
		}

		w.logger.Debugw("host not seen for a while, pinging",
			zap.String("ipv6", netip.AddrFrom16(expiredAddr.As16()).String()),
			zap.String("mac", expiredAddr.Hw.String()),
			zap.String("iface", iface.Name),
			zap.Int("remainingEvents", int(remainingEvents)),
		)

		if pingConn != nil {
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

	processNDP := func(receivedAddr netip.Addr, receivedNetHardwareAddr net.HardwareAddr) {
		_, existing := w.State.Register(receivedNetHardwareAddr, receivedAddr, iface.Name, w.lifetime, addrOnExpiration)
		if !existing && ndpConn != nil {
			ndpConn.IncrementHostsFound()
		}
	}

	ndpConn, err = ndp.ListenForNDP(&iface, addr, processNDP)
	if err != nil {
		w.logger.Errorw("error listening for NDP",
			zap.String("interface", iface.Name),
			zap.String("address", addr.String()),
			zap.Error(err),
		)
		return
	}
	defer ndpConn.Close()

	// manage ICMP
	var pingCallback func(netip.Addr)
	pingConn, err = ping.ListenForICMP(&iface, addr, func(remoteIP netip.Addr) {
		if pingCallback != nil {
			pingCallback(remoteIP)
		}
	})
	if err != nil {
		w.logger.Errorw("error listening for ICMP",
			zap.String("interface", iface.Name),
			zap.String("address", addr.String()),
			zap.Error(err),
		)
		return
	}
	defer pingConn.Close()
	pingCallback = onFoundAddrFunc(ndpConn, pingConn, &iface, w.logger, "ICMP echo response")

	// manage SSDP
	var ssdpCallback func(netip.Addr)
	ssdpConn, err = ssdp.ListenForSSDP(&iface, addr, func(remoteIP netip.Addr) {
		if ssdpCallback != nil {
			ssdpCallback(remoteIP)
		}
	})
	if err != nil {
		w.logger.Errorw("error listening for SSDP",
			zap.String("interface", iface.Name),
			zap.String("address", addr.String()),
			zap.Error(err),
		)
		return
	}
	defer ssdpConn.Close()
	ssdpCallback = onFoundAddrFunc(ndpConn, ssdpConn, &iface, w.logger, "SSDP announcement")

	// manage WSD
	var wsdCallback func(netip.Addr)
	wsdConn, err = wsd.ListenForWSD(&iface, addr, func(remoteIP netip.Addr) {
		if wsdCallback != nil {
			wsdCallback(remoteIP)
		}
	})
	if err != nil {
		w.logger.Errorw("error listening for WSD",
			zap.String("interface", iface.Name),
			zap.String("address", addr.String()),
			zap.Error(err),
		)
		return
	}
	defer wsdConn.Close()
	wsdCallback = onFoundAddrFunc(ndpConn, wsdConn, &iface, w.logger, "WSD message")

	w.pcMutex.Lock()
	w.protocolConns[addr.String()] = &InterfaceProcesses{
		InterfaceName: iface.Name,
		Address:       addr,
		Protocols: []*DiscoveryProtocol{
			{Name: "ndp", Worker: ndpConn},
			{Name: "ping", Worker: pingConn},
			{Name: "ssdp", Worker: ssdpConn},
			{Name: "wsd", Worker: wsdConn},
		},
	}
	w.pcMutex.Unlock()
	defer func() {
		w.pcMutex.Lock()
		delete(w.protocolConns, addr.String())
		w.pcMutex.Unlock()
	}()

	discover := func() {
		if !w.discoveryActive {
			return
		}

		w.logger.Infof("active discovery started on %s %s", iface.Name, addr.String())
		startNDPDiscovery(ndpConn, w.logger)
		startPingMulticast(pingConn, w.logger)
		startSSDPDiscovery(ssdpConn, w.logger)
		startWSDiscovery(wsdConn, w.logger)
	}

	// Bootstrap discovery
	discover()

	// Periodic re-discovery
	ticker := time.NewTicker(w.rediscover)
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
	} else {
		return &InvalidInterfaceError{iface}
	}
}

func onFoundAddrFunc(ndpConn *ndp.Conn, protocolConn HostCounter, iface *net.Interface, logger *zap.SugaredLogger, logString string) func(remoteIP netip.Addr) {
	return func(remoteIP netip.Addr) {
		logger.Debugw(logString+" received",
			zap.String("remote", remoteIP.String()),
			zap.String("interface", iface.Name),
		)
		if protocolConn != nil {
			protocolConn.IncrementHostsFound()
		}
		if ndpConn != nil {
			ndpConn.SendNeighborSolicitation(&remoteIP)
		}
	}
}

func startNDPDiscovery(ndpConn *ndp.Conn, logger *zap.SugaredLogger) {
	logger.Debugw("send ICMPv6 Neighbor Solicitation to all-nodes link-local multicast address",
		zap.String("source", ndpConn.GetListenAddr().String()),
	)

	err := ndpConn.DiscoverMulticast()
	if err != nil {
		logger.Fatalw("send ICMPv6 Neighbor Solicitation failed",
			err,
			zap.String("source", ndpConn.GetListenAddr().String()),
		)
	}
}

func startPingMulticast(pingConn *ping.Conn, logger *zap.SugaredLogger) {
	logger.Debugw("PING all-nodes link-local multicast",
		zap.String("listener", pingConn.GetListenAddr().String()),
	)

	err := pingConn.DiscoverMulticast()
	if err != nil {
		logger.Fatalf("PING discover multicast failed",
			err,
			zap.String("source", pingConn.GetListenAddr().String()),
		)
	}
}

func startSSDPDiscovery(ssdpConn *ssdp.Conn, logger *zap.SugaredLogger) {
	logger.Debugw("SSDP discover multicast",
		zap.String("listener", ssdpConn.GetListenAddrPort().String()),
	)

	err := ssdpConn.DiscoverMulticast()
	if err != nil {
		logger.Fatalf("SSDP discover multicast failed",
			err,
			zap.String("source", ssdpConn.GetListenAddrPort().String()),
		)
	}
}

func startWSDiscovery(wsdConn *wsd.Conn, logger *zap.SugaredLogger) {
	logger.Debugw("WSD discover multicast",
		zap.String("listener", wsdConn.GetListenAddrPort().String()),
	)

	err := wsdConn.DiscoverMulticast()
	if err != nil {
		logger.Fatalf("WSD discover multicast failed",
			err,
			zap.String("source", wsdConn.GetListenAddrPort().String()),
		)
	}
}
