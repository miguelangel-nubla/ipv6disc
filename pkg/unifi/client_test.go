package unifi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fake is a Network API as the real ones answer: UniFi OS, with an API key or a login whose CSRF
// token every write must send, and which it renews at each, under /proxy/network; or a
// self-hosted Network Application, with a login of its own, which answers UniFi OS's as its API
// does without a session, and no prefix. Its one path, of the site default, echoes what it was
// sent, with the query.
type fake struct {
	unifiOS bool

	mutex    sync.Mutex
	sessions map[string]string // cookie: its CSRF token
	logins   int
}

func newFake(t *testing.T, unifiOS bool) (*fake, *httptest.Server) {
	f := &fake{unifiOS: unifiOS, sessions: map[string]string{}}
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	return f, server
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	fail := func(status int, body string) {
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}
	switch {
	case r.URL.Path == "/api/auth/login" && !f.unifiOS:
		fail(http.StatusUnauthorized, `{"meta":{"rc":"error","msg":"api.err.LoginRequired"},"data":[]}`)
		return
	case r.URL.Path == "/api/auth/login" && f.unifiOS, r.URL.Path == "/api/login" && !f.unifiOS:
		var body struct{ Username, Password string }
		json.NewDecoder(r.Body).Decode(&body)
		if body.Password != "secret" {
			fail(http.StatusForbidden, `{"message":"Invalid username or password"}`)
			return
		}
		f.logins++
		cookie, csrf := fmt.Sprint("s", f.logins), fmt.Sprint("c", f.logins)
		f.sessions[cookie] = csrf
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: cookie, Path: "/"})
		if f.unifiOS {
			w.Header().Set("X-Csrf-Token", csrf)
		}
		fmt.Fprint(w, `{}`)
		return
	}
	prefix := ""
	if f.unifiOS {
		prefix = "/proxy/network"
	}
	if r.URL.Path != prefix+"/v2/api/site/default/thing" {
		fail(http.StatusNotFound, `<html>404</html>`)
		return
	}
	if key := r.Header.Get("X-API-KEY"); key != "" {
		if key != "the-key" {
			fail(http.StatusUnauthorized, `{"error":{"code":401,"message":"Unauthorized"}}`)
			return
		}
	} else {
		cookie, err := r.Cookie("TOKEN")
		csrf, ok := "", false
		if err == nil {
			csrf, ok = f.sessions[cookie.Value]
		}
		if !ok {
			fail(http.StatusUnauthorized, `{"code":"api.err.UserNotAuthenticated","message":"User not authenticated"}`)
			return
		}
		if f.unifiOS && r.Method != http.MethodGet {
			if r.Header.Get("X-Csrf-Token") != csrf {
				fail(http.StatusForbidden, `{"message":"Invalid CSRF token"}`)
				return
			}
			f.sessions[cookie.Value] = csrf + "+"
			w.Header().Set("X-Updated-Csrf-Token", csrf+"+")
		}
	}
	var sent map[string]any
	json.NewDecoder(r.Body).Decode(&sent)
	if sent["value"] == "bad" {
		fail(http.StatusBadRequest, `{"code":"api.err.Invalid","details":{"invalid_fields":["value"]},"message":"Invalid IPv6 Address"}`)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"method": r.Method, "query": r.URL.RawQuery, "sent": sent})
}

type echo struct {
	Method string
	Query  string
	Sent   map[string]any
}

// A user of UniFi OS: one login, the CSRF token with each write, the one renewed taken; and a
// login again, once, when the session ends. A self-hosted one: its own login, and no prefix.
func TestClientLogin(t *testing.T) {
	for _, unifiOS := range []bool{true, false} {
		f, server := newFake(t, unifiOS)
		c, err := New(Config{Address: server.URL, Username: "admin", Password: "secret"}, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for i := range 3 {
			var got echo
			if err := c.Call(context.Background(), http.MethodPost, "/thing?x=1", map[string]any{"i": i}, &got); err != nil {
				t.Fatalf("UniFi OS %v, write %d: %v", unifiOS, i+1, err)
			}
			if got.Method != "POST" || got.Query != "x=1" || got.Sent["i"] != float64(i) {
				t.Errorf("UniFi OS %v: %+v", unifiOS, got)
			}
		}
		f.mutex.Lock()
		f.sessions = map[string]string{}
		f.mutex.Unlock()
		if err := c.Call(context.Background(), http.MethodPut, "/thing", map[string]any{}, nil); err != nil {
			t.Fatalf("UniFi OS %v, after the session ended: %v", unifiOS, err)
		}
		if f.logins != 2 {
			t.Errorf("UniFi OS %v: %d logins, want 2", unifiOS, f.logins)
		}
	}
}

// Each refusal is an *Error that says why: of a key, of a site or path that isn't there, of a
// record refused, with its field; and a refused login.
func TestClientErrors(t *testing.T) {
	_, os := newFake(t, true)
	_, self := newFake(t, false)
	for _, c := range []struct {
		name   string
		config Config
		path   string
		body   any
		status int
		want   string
	}{
		{"a wrong key", Config{Address: os.URL, APIKey: "wrong"}, "/thing", nil, 401, "HTTP 401: the API key is refused: create one in UniFi OS"},
		{"another site", Config{Address: os.URL, APIKey: "the-key", Site: "other"}, "/thing", nil, 404, `HTTP 404: not here: the site "other", or the address, is wrong. An API key is of UniFi OS alone`},
		{"a key, self-hosted", Config{Address: self.URL, APIKey: "the-key"}, "/thing", nil, 404, "a self-hosted Network Application needs username and password"},
		{"a record refused", Config{Address: os.URL, APIKey: "the-key"}, "/thing", map[string]any{"value": "bad"}, 400, "HTTP 400: Invalid IPv6 Address (value)"},
		{"a wrong password", Config{Address: os.URL, Username: "admin", Password: "wrong"}, "/thing", nil, 0, "logging in: HTTP 403: the username or the password is refused"},
	} {
		t.Run(c.name, func(t *testing.T) {
			client, err := New(c.config, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			err = client.Call(context.Background(), http.MethodPost, c.path, c.body, nil)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("got %v\nwant %s", err, c.want)
			}
			var e *Error
			if c.status != 0 && (!errors.As(err, &e) || e.Status != c.status) {
				t.Errorf("not an *Error of %d: %#v", c.status, err)
			}
		})
	}
}

func TestConfigCheck(t *testing.T) {
	for config, want := range map[Config]string{
		{}:                                    "no address",
		{Address: "192.168.1.1", APIKey: "k"}: "invalid address",
		{Address: "https://u", APIKey: "k", Username: "a"}: "not both",
		{Address: "https://u", Username: "a"}:              "give api_key",
	} {
		if err := config.Check(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: got %v, want %s", config, err, want)
		}
	}
	c, err := New(Config{Address: "https://u", APIKey: "k"}, nil, 0)
	if err != nil || c.Site() != "default" {
		t.Errorf("%v, site %q", err, c.Site())
	}
}
