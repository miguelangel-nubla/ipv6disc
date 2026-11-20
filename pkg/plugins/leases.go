package plugins

import (
	"bufio"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

// Lease is the host name of a DHCP lease: the one the client gave its server, or the server has
// for it. With the MAC of the client, or, where the lease has none, as a DHCPv6 one, which knows
// its client by a DUID, with the address leased: the neighbor table tells whose it is.
type Lease struct {
	MAC  net.HardwareAddr
	IP   netip.Addr
	Name string
}

// RegisterLeases registers the names of the leases, as names of the hosts with their MACs, when
// the state takes names. A lease without a MAC is of the host that neighbors, the addresses of
// the neighbor table read at the same time, has at its address, if any. The names are as the
// clients gave them: the state cleans them, and leaves out those that are none, as a *.
func RegisterLeases(state *ipv6disc.State, leases []Lease, neighbors map[netip.Addr]net.HardwareAddr, source string, lifetime time.Duration) {
	if !state.Names() {
		return
	}
	for _, lease := range leases {
		mac := lease.MAC
		if len(mac) == 0 {
			mac = neighbors[lease.IP.Unmap().WithZone("")]
		}
		// A group's MAC is no host's.
		if len(mac) == 0 || mac[0]&1 != 0 {
			continue
		}
		state.RegisterName(mac, lease.Name, source, lifetime)
	}
}

// ParseDnsmasqLeases reads the leases file of dnsmasq, /tmp/dhcp.leases on OpenWrt:
//
//	1700003600 00:1a:2b:3c:4d:5e 192.168.1.50 laptop 01:00:1a:2b:3c:4d:5e
//	1700003600 00:1a:2b:3c:4d:5f 192.168.1.51 * *
//	duid 00:01:00:01:2c:5b:8f:6e:00:1a:2b:3c:4d:01
//	1700003600 1052436 fd00::1c3 phone 00:01:00:01:2b:11:22:33:00:1a:2b:3c:4d:60
//
// A DHCPv6 lease has the IAID of its client where a DHCPv4 one has the MAC: it comes without.
// dnsmasq keeps no lease that expired, so all of them count. The lines that are no lease, as the
// server's DUID, are skipped.
func ParseDnsmasqLeases(output string) []Lease {
	var leases []Lease
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || !isNumber(fields[0]) {
			continue
		}
		ip, err := netip.ParseAddr(fields[2])
		if err != nil {
			continue
		}
		lease := Lease{IP: ip, Name: fields[3]}
		if ip.Is4() {
			if lease.MAC, err = net.ParseMAC(fields[1]); err != nil {
				continue
			}
		}
		leases = append(leases, lease)
	}
	return leases
}

func isNumber(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

// ParseHosts reads a hosts file, as the one odhcpd writes of its DHCPv6 leases,
// /tmp/hosts/odhcpd on OpenWrt: an address and its names, the first of which counts.
//
//	# br-lan 00010001... 1052436 phone 1700003600 1c3 128 fd00::1c3/128
//	fd00::1c3	phone.lan	phone
func ParseHosts(output string) []Lease {
	var leases []Lease
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if ip, err := netip.ParseAddr(fields[0]); err == nil {
			leases = append(leases, Lease{IP: ip, Name: fields[1]})
		}
	}
	return leases
}

// ParseISCLeases reads the leases file of ISC dhcpd, as pfSense and OPNsense have it, at
// /var/dhcpd/var/db/dhcpd.leases:
//
//	lease 192.168.1.50 {
//	  binding state active;
//	  hardware ethernet 00:1a:2b:3c:4d:5e;
//	  client-hostname "laptop";
//	}
//
// The file is a journal: the last entry of an address is its lease, and only one whose binding
// state is active counts, as the others are of hosts that left.
func ParseISCLeases(output string) []Lease {
	leases := make(map[netip.Addr]Lease)
	var current Lease
	var active, inside bool
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(strings.TrimSuffix(strings.TrimSpace(scanner.Text()), ";"))
		switch {
		case len(fields) == 3 && fields[0] == "lease" && fields[2] == "{":
			ip, err := netip.ParseAddr(fields[1])
			current, active, inside = Lease{IP: ip}, false, err == nil
		case !inside:
		case len(fields) == 1 && fields[0] == "}":
			if active && len(current.MAC) > 0 && current.Name != "" {
				leases[current.IP] = current
			} else {
				delete(leases, current.IP)
			}
			inside = false
		case len(fields) == 3 && fields[0] == "binding" && fields[1] == "state":
			active = fields[2] == "active"
		case len(fields) == 3 && fields[0] == "hardware" && fields[1] == "ethernet":
			current.MAC, _ = net.ParseMAC(fields[2])
		case len(fields) >= 2 && fields[0] == "client-hostname":
			// A name with a space in it stays whole, for the state to make something of.
			current.Name = strings.Trim(strings.Join(fields[1:], " "), `"`)
		}
	}
	return sortedLeases(leases)
}

// ParseKeaLeases reads the lease files of Kea, the CSV ones of its memfile backend, of DHCPv4 and
// of DHCPv6, one after the other or alone: each begins with the names of its columns.
//
//	address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
//	192.168.1.50,00:1a:2b:3c:4d:5e,01:00:1a:2b:3c:4d:5e,7200,1700003600,1,0,0,laptop.lan.,0,,0
//
// The file is a journal: the last line of an address is its lease, and only one in the state 0,
// assigned, counts.
func ParseKeaLeases(output string) []Lease {
	leases := make(map[netip.Addr]Lease)
	var columns []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Split(strings.TrimSpace(scanner.Text()), ",")
		if fields[0] == "address" {
			columns = fields
			continue
		}
		column := func(name string) string {
			if i := slices.Index(columns, name); i >= 0 && i < len(fields) {
				return fields[i]
			}
			return ""
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}
		mac, _ := net.ParseMAC(column("hwaddr"))
		if name := column("hostname"); column("state") == "0" && name != "" {
			leases[ip] = Lease{MAC: mac, IP: ip, Name: name}
		} else {
			delete(leases, ip)
		}
	}
	return sortedLeases(leases)
}

func sortedLeases(leases map[netip.Addr]Lease) []Lease {
	result := make([]Lease, 0, len(leases))
	for _, lease := range leases {
		result = append(result, lease)
	}
	slices.SortFunc(result, func(a, b Lease) int { return a.IP.Compare(b.IP) })
	return result
}
