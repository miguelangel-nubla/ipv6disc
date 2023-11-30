package worker

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
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
	logger *zap.SugaredLogger
	Table  *Table
	ttl    time.Duration
}

func NewWorker(table *Table, ttl time.Duration, logger *zap.SugaredLogger) *Worker {
	return &Worker{
		logger: logger,
		Table:  table,
		ttl:    ttl,
	}
}

func (w *Worker) Start() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("error getting interfaces: %w", err)
	}

	noValidAddr := fmt.Errorf("no valid IPv6 address found")
	var invalidIface = &InvalidInterfaceError{}
	for _, iface := range ifaces {
		err = w.StartInterface(&iface)
		switch {
		case err == nil:
			// At least one address was valid
			noValidAddr = nil
			continue
		case errors.As(err, &invalidIface):
			// Ignore invalid interfaces
			continue
		default:
			return err
		}
	}

	return noValidAddr
}

func (w *Worker) StartInterface(iface *net.Interface) error {
	err := isValidInterface(iface)
	if err != nil {
		return err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("error getting IPv6 addresses for interface %s: %w", iface.Name, err)
	}

	noValidAddr := fmt.Errorf("no valid IPv6 addresses found: %w", &InvalidInterfaceError{iface: iface})
	for _, a := range addrs {
		addr := netip.MustParseAddr(a.(*net.IPNet).IP.String())
		if !addr.Is4() && !addr.IsLinkLocalUnicast() {
			noValidAddr = nil
			go w.StartInterfaceAddr(*iface, addr)
		}
	}

	return noValidAddr
}

func (w *Worker) StartInterfaceAddr(iface net.Interface, addr netip.Addr) {
	var err error
	var ndpConn *ndp.Conn
	var pingConn *ping.Conn
	var ssdpConn *ssdp.Conn
	var wsdConn *wsd.Conn

	// manage NDP
	onFoundLinkLayerAddr := func(hostAddr netip.Addr, linkLayerAddr net.HardwareAddr) {
		onExpiration := func(info *IPAddressInfo, attempt int) {
			address := info.GetAddress()

			if attempt == 0 {
				w.logger.Infow("host expired",
					zap.String("ipv6", netip.AddrFrom16(address.As16()).String()),
					zap.String("mac", linkLayerAddr.String()),
					zap.String("iface", address.Zone()),
				)
			} else {
				w.logger.Debugw("host not seen for a while",
					zap.String("ipv6", netip.AddrFrom16(address.As16()).String()),
					zap.String("mac", linkLayerAddr.String()),
					zap.String("iface", address.Zone()),
					zap.Int("attempt", attempt),
				)
			}

			// do ping
			if pingConn != nil {
				w.logger.Debugw("ping",
					zap.String("ipv6", address.String()),
				)
				target := netip.MustParseAddr(address.String())
				err := pingConn.SendPing(&target)
				if err != nil {
					w.logger.Errorw("ping failed",
						zap.String("ipv6", address.String()),
						zap.Error(err),
					)
				}
			} else {
				w.logger.Errorw("unable to ping, connection not available",
					zap.String("ipv6", address.String()),
				)
			}
			if time.Now().After(info.GetExpiration()) {
				w.Table.macs[linkLayerAddr.String()].Remove(hostAddr)
			}
		}
		existing := w.Table.Add(linkLayerAddr, hostAddr, w.ttl, onExpiration)
		if existing {
			w.logger.Debugw("ttl refreshed",
				zap.String("ipv6", hostAddr.String()),
				zap.String("mac", linkLayerAddr.String()),
			)
		} else {
			w.logger.Infow("host identified",
				zap.String("ipv6", netip.AddrFrom16(hostAddr.As16()).String()),
				zap.String("mac", linkLayerAddr.String()),
				zap.String("iface", hostAddr.Zone()),
			)
		}
	}

	ndpConn, err = ndp.ListenForNDP(&iface, addr, onFoundLinkLayerAddr)
	if err != nil {
		w.logger.Fatalf("error listening for NDP on interface %s: %s", iface.Name, err)
	}
	defer ndpConn.Close()

	// manage ICMP
	pingConn, err = ping.ListenForICMP(addr, onFoundAddrFunc(ndpConn, &iface, w.logger, "ICMP echo response"))
	if err != nil {
		w.logger.Fatalf("Error listening for ICMP on interface %s: %s", iface.Name, err)
	}
	defer pingConn.Close()

	// manage SSDP
	ssdpConn, err = ssdp.ListenForSSDP(addr, onFoundAddrFunc(ndpConn, &iface, w.logger, "SSDP announcement"))
	if err != nil {
		w.logger.Fatalf("error listening for SSDP on interface %s: %s", iface.Name, err)
	}
	defer ssdpConn.Close()

	// manage WSD
	wsdConn, err = wsd.ListenForWSD(addr, onFoundAddrFunc(ndpConn, &iface, w.logger, "WSD message"))
	if err != nil {
		w.logger.Fatalf("error listening for WSD on interface %s: %s", iface.Name, err)
	}
	defer wsdConn.Close()

	discover := func() {
		startNDPDiscovery(ndpConn, w.logger)
		startPingMulticast(pingConn, w.logger)
		startSSDPDiscovery(ssdpConn, w.logger)
		startWSDiscovery(wsdConn, w.logger)
	}

	// Bootstrap discovery
	discover()

	// Periodic re-discovery
	ticker := time.NewTicker(w.ttl / 3)
	defer ticker.Stop()
	for range ticker.C {
		discover()
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

func onFoundAddrFunc(ndpConn *ndp.Conn, iface *net.Interface, logger *zap.SugaredLogger, logString string) func(remoteIP netip.Addr) {
	return func(remoteIP netip.Addr) {
		logger.Debugw(logString+" received",
			zap.String("remote", remoteIP.String()),
			zap.String("interface", iface.Name),
		)
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
