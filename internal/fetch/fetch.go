// Package fetch asks a host of the link for one document over HTTP, as the description a device
// points to in its answer to a search: bounded in every way, as what it is told to fetch is
// that host's word.
package fetch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const (
	// Timeout is how long a document may take, from the connection to its last byte.
	Timeout = 3 * time.Second
	// Limit is the most that is read of one: a longer one is an error.
	Limit = 256 << 10
	// AtOnce is how many are fetched at a time, by a Fetcher: one more is not, and is left.
	AtOnce = 4
)

// Target is where a URL a host gave points to, if at that host itself: its port and its path.
// Only a plain http URL whose host is the address the host answered from, written as an address:
// a URL to another address is never followed. With named, a URL whose host is a name is taken
// too, for its port and its path alone: the name is never resolved, and what is fetched is at
// the address that answered, whatever it calls itself.
func Target(raw string, from netip.Addr, named bool) (port int, path string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Opaque != "" || u.Hostname() == "" {
		return 0, "", false
	}
	if host, err := netip.ParseAddr(u.Hostname()); err == nil {
		if host.Unmap().WithZone("") != from.Unmap().WithZone("") {
			return 0, "", false
		}
	} else if !named {
		return 0, "", false
	}
	port = 80
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil || port <= 0 || port > 65535 {
			return 0, "", false
		}
	}
	return port, u.RequestURI(), true
}

// Fetcher fetches for the listener of an interface, a few at a time, until it is closed.
type Fetcher struct {
	iface  string
	ctx    context.Context
	cancel context.CancelFunc
	slots  chan struct{}
	wait   sync.WaitGroup
}

// New makes a Fetcher that connects out of the interface of that name.
func New(iface string) *Fetcher {
	ctx, cancel := context.WithCancel(context.Background())
	return &Fetcher{iface: iface, ctx: ctx, cancel: cancel, slots: make(chan struct{}, AtOnce)}
}

// Go fetches the document at path of the port of addr, in the background, and calls done with
// it if it comes: by a GET, or with a body by a POST of that content type. It returns whether
// it started: not when AtOnce are under way, nor once closed.
func (f *Fetcher) Go(addr netip.Addr, port int, path, contentType string, body []byte, done func([]byte)) bool {
	select {
	case f.slots <- struct{}{}:
	default:
		return false
	}
	if f.ctx.Err() != nil {
		<-f.slots
		return false
	}
	f.wait.Add(1)
	go func() {
		defer f.wait.Done()
		defer func() { <-f.slots }()
		if document, err := Do(f.ctx, f.iface, addr, port, path, contentType, body); err == nil {
			done(document)
		}
	}()
	return true
}

// Close ends what is under way, and waits for it.
func (f *Fetcher) Close() {
	f.cancel()
	f.wait.Wait()
}

// Do fetches the document at path of the port of addr, connecting to that address alone, out
// of iface when it is a link-local one: within Timeout, of Limit bytes at most, with no proxy,
// and no redirection followed. Anything but a 200 is an error.
func Do(ctx context.Context, iface string, addr netip.Addr, port int, path, contentType string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()

	addr = addr.Unmap().WithZone("")
	dial := addr
	if addr.Is6() && addr.IsLinkLocalUnicast() {
		dial = addr.WithZone(iface)
	}
	destination := netip.AddrPortFrom(dial, uint16(port)).String()
	client := &http.Client{
		Transport: &http.Transport{
			// Whatever the request says, the connection is to the address that answered.
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", destination)
			},
			Proxy:                  nil,
			DisableKeepAlives:      true,
			MaxResponseHeaderBytes: 16 << 10,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()

	method, reader := http.MethodGet, io.Reader(nil)
	if body != nil {
		method, reader = http.MethodPost, bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://"+netip.AddrPortFrom(addr, uint16(port)).String()+path, reader)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	request.Header.Set("User-Agent", "ipv6disc")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", response.StatusCode)
	}
	document, err := io.ReadAll(io.LimitReader(response.Body, Limit+1))
	if err != nil {
		return nil, err
	}
	if len(document) > Limit {
		return nil, errors.New("document too long")
	}
	return document, nil
}
