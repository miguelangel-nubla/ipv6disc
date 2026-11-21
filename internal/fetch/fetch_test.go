package fetch

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A URL a host gave is followed only to that host itself: at the address it answered from. One
// to another address, by a name, over another scheme, or that can't be read, is not.
func TestTarget(t *testing.T) {
	from := netip.MustParseAddr("fe80::20")
	for raw, want := range map[string]string{
		"http://[fe80::20]:49152/description.xml":     "49152 /description.xml",
		"http://[fe80::20%25eth0]:49152/desc.xml?a=b": "49152 /desc.xml?a=b",
		"http://[fe80::20]/":                          "80 /",
		"http://[fe80::20]":                           "80 /",
		"http://[fe80::66]:49152/description.xml":     "",
		"http://[2001:db8::20]:49152/description.xml": "",
		"http://192.168.1.20:49152/description.xml":   "",
		"http://printer.lan:49152/description.xml":    "",
		"https://[fe80::20]:49152/description.xml":    "",
		"http://user@[fe80::20]:49152/":               "",
		"http://[fe80::20]:0/":                        "",
		"http://[fe80::20]:99999/":                    "",
		"file:///etc/passwd":                          "",
		"http:opaque":                                 "",
		"//[fe80::20]/":                               "",
		"":                                            "",
		"http://[fe80::20":                            "",
	} {
		port, path, ok := Target(raw, from.WithZone("eth0"), false)
		if got := fmt.Sprintf("%d %s", port, path); ok != (want != "") || ok && got != want {
			t.Errorf("%q: %q, %v; want %q", raw, got, ok, want)
		}
	}
	// An IPv4 host, also as it comes from a socket of both families.
	if port, path, ok := Target("http://192.168.1.20:5357/x", netip.MustParseAddr("::ffff:192.168.1.20"), false); !ok || port != 5357 || path != "/x" {
		t.Errorf("an IPv4 host: %d %s %v", port, path, ok)
	}
	// With a name in place of its address, only its port and its path are its word: an address
	// that is another's is still not followed.
	if port, path, ok := Target("http://winbox:5357/uuid", from, true); !ok || port != 5357 || path != "/uuid" {
		t.Errorf("a name, taken for its port and path: %d %s %v", port, path, ok)
	}
	if _, _, ok := Target("http://[fe80::66]:5357/uuid", from, true); ok {
		t.Error("another address followed, with names taken")
	}
}

func serverAt(t *testing.T, handler http.HandlerFunc) (netip.Addr, int) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	addr := server.Listener.Addr().(*net.TCPAddr).AddrPort()
	return addr.Addr(), int(addr.Port())
}

// A document is fetched from the address given alone, within the bounds: its length, its time,
// no redirection followed, and nothing but a 200 taken.
func TestDo(t *testing.T) {
	var elsewhere atomic.Int32
	other, otherPort := serverAt(t, func(w http.ResponseWriter, r *http.Request) { elsewhere.Add(1) })
	var requests []string
	var mutex sync.Mutex
	addr, port := serverAt(t, func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		requests = append(requests, fmt.Sprintf("%s %s %s %s", r.Method, r.URL.RequestURI(), r.Host, r.Header.Get("Content-Type")))
		mutex.Unlock()
		switch r.URL.Path {
		case "/long":
			w.Write([]byte(strings.Repeat("x", Limit+1)))
		case "/limit":
			w.Write([]byte(strings.Repeat("x", Limit)))
		case "/redirect":
			http.Redirect(w, r, fmt.Sprintf("http://%s/", netip.AddrPortFrom(other, uint16(otherPort))), http.StatusFound)
		case "/missing":
			http.NotFound(w, r)
		case "/slow":
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
		default:
			w.Write([]byte("the document"))
		}
	})
	ctx := context.Background()
	if got, err := Do(ctx, "eth0", addr, port, "/description.xml?a=b", "", nil); err != nil || string(got) != "the document" {
		t.Errorf("a document: %q, %v", got, err)
	}
	if got, err := Do(ctx, "eth0", addr, port, "/post", "application/soap+xml", []byte("<a/>")); err != nil || string(got) != "the document" {
		t.Errorf("a document asked for by a POST: %q, %v", got, err)
	}
	if got, err := Do(ctx, "eth0", addr, port, "/limit", "", nil); err != nil || len(got) != Limit {
		t.Errorf("a document of the most that is read: %d bytes, %v", len(got), err)
	}
	for _, path := range []string{"/long", "/redirect", "/missing"} {
		if got, err := Do(ctx, "eth0", addr, port, path, "", nil); err == nil {
			t.Errorf("%s: %d bytes taken", path, len(got))
		}
	}
	if elsewhere.Load() != 0 {
		t.Error("a redirection to another host was followed")
	}
	short, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := Do(short, "eth0", addr, port, "/slow", "", nil); err == nil || time.Since(start) > 3*time.Second {
		t.Errorf("a document that doesn't come: %v, after %s", err, time.Since(start))
	}
	// Nothing listens there.
	if _, err := Do(ctx, "eth0", netip.MustParseAddr("127.0.0.1"), 1, "/", "", nil); err == nil {
		t.Error("a document from a port nothing listens on")
	}
	mutex.Lock()
	defer mutex.Unlock()
	host := netip.AddrPortFrom(addr, uint16(port)).String()
	if len(requests) < 2 || requests[0] != "GET /description.xml?a=b "+host+" " || requests[1] != "POST /post "+host+" application/soap+xml" {
		t.Errorf("requests: %q", requests)
	}
	if Timeout > 5*time.Second || Limit > 1<<20 {
		t.Errorf("the bounds: %s, %d bytes", Timeout, Limit)
	}
}

// A Fetcher fetches a few at a time, and no more: one more is left. Closed, it ends what is
// under way, waits for it, and starts nothing.
func TestFetcher(t *testing.T) {
	release := make(chan struct{})
	var started atomic.Int32
	addr, port := serverAt(t, func(w http.ResponseWriter, r *http.Request) {
		started.Add(1)
		select {
		case <-release:
			w.Write([]byte("the document"))
		case <-r.Context().Done():
		}
	})
	f := New("eth0")
	var done atomic.Int32
	for i := range AtOnce {
		if !f.Go(addr, port, "/", "", nil, func([]byte) { done.Add(1) }) {
			t.Fatalf("the fetch %d did not start", i+1)
		}
	}
	if f.Go(addr, port, "/", "", nil, func([]byte) { done.Add(1) }) {
		t.Errorf("more than %d fetched at once", AtOnce)
	}
	deadline := time.Now().Add(5 * time.Second)
	for started.Load() < AtOnce && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
	for done.Load() < AtOnce && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if done.Load() != AtOnce {
		t.Fatalf("%d documents fetched, want %d", done.Load(), AtOnce)
	}

	// One that waits when it is closed ends, and its document is not told.
	slowAddr, slowPort := serverAt(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	for !f.Go(slowAddr, slowPort, "/", "", nil, func([]byte) { t.Error("a document told after Close") }) {
		time.Sleep(5 * time.Millisecond)
	}
	closed := make(chan struct{})
	go func() { f.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not end what was under way")
	}
	if f.Go(addr, port, "/", "", nil, func([]byte) {}) {
		t.Error("a fetch started after Close")
	}
}
