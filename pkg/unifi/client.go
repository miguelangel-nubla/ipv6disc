// Package unifi is a client of the UniFi Network API: of a UniFi OS console or UniFi OS Server,
// with an API key or a user, or of a self-hosted Network Application, with a user. It logs in,
// keeps the session, and tells the API's refusals with what to do about them.
package unifi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config is how to reach a UniFi Network and log in: an API key, or a username and password.
type Config struct {
	// The console, as https://192.168.1.1, or the self-hosted Network Application, as
	// https://192.168.1.2:8443.
	Address string
	// An API key, of UniFi OS alone; or a local user, of either.
	APIKey   string
	Username string
	Password string
	// The site's name in the API: default, when empty.
	Site string
}

// Check tells what is wrong with the config: no address, an address that isn't one of HTTP, or a
// key and a user, or neither.
func (c Config) Check() error {
	u, err := url.Parse(c.Address)
	switch {
	case c.Address == "":
		return errors.New("no address: give the console's, as https://192.168.1.1")
	case err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "":
		return fmt.Errorf("invalid address %q: give the console's, as https://192.168.1.1", c.Address)
	case c.APIKey != "" && (c.Username != "" || c.Password != ""):
		return errors.New("give api_key or username and password, not both")
	case c.APIKey == "" && (c.Username == "" || c.Password == ""):
		return errors.New("give api_key, an API key of UniFi OS, or username and password, of a local user")
	}
	return nil
}

// Client calls the UniFi Network API of a site, one call at a time. A user logs in at the first
// call, and again once when the session is refused; the session is kept between calls, as UniFi
// OS limits how often one logs in.
type Client struct {
	config Config
	http   *http.Client

	mutex    sync.Mutex
	loggedIn bool
	// Whether the server is UniFi OS, whose Network API is under /proxy/network: always, with an
	// API key; learned at the login of a user.
	unifiOS bool
	csrf    string
}

// New is a client of config, which must Check, with the TLS given, as of a certificate checked by
// its fingerprint, and the timeout of each request: none, 0, leaves it to the context of each
// call.
func New(config Config, tlsConfig *tls.Config, timeout time.Duration) (*Client, error) {
	if err := config.Check(); err != nil {
		return nil, err
	}
	if config.Site == "" {
		config.Site = "default"
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &Client{
		config:  config,
		http:    &http.Client{Jar: jar, Timeout: timeout, Transport: &http.Transport{TLSClientConfig: tlsConfig}},
		unifiOS: config.APIKey != "",
	}, nil
}

// Site is the site the client calls.
func (c *Client) Site() string { return c.config.Site }

// Call sends method to path of the site's Network API, of its version 2, as /static-dns or
// /clients/active?includeUnifiDevices=true, with body when there is one, and reads the answer into
// out when there is where to. An answer that isn't 200 is an *Error.
func (c *Client) Call(ctx context.Context, method, path string, body, out any) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.config.APIKey == "" && !c.loggedIn {
		if err := c.login(ctx); err != nil {
			return err
		}
	}
	status, answer, err := c.do(ctx, method, c.sitePath(path), body)
	if err == nil && status == http.StatusUnauthorized && c.config.APIKey == "" {
		c.loggedIn = false
		if err := c.login(ctx); err != nil {
			return err
		}
		status, answer, err = c.do(ctx, method, c.sitePath(path), body)
	}
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return c.refused(status, answer)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(answer, out); err != nil {
		return fmt.Errorf("HTTP %d: not an answer of the UniFi Network API: %w", status, err)
	}
	return nil
}

// sitePath is the path of the site's version 2 API: under /proxy/network on UniFi OS.
func (c *Client) sitePath(path string) string {
	p := "/v2/api/site/" + url.PathEscape(c.config.Site) + path
	if c.unifiOS {
		p = "/proxy/network" + p
	}
	return p
}

// do sends a request to path of the server, its query too, with the API key or the session, and
// returns the status and the answer. It keeps the CSRF token UniFi OS gives at its login, and
// renews.
func (c *Client) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	base, err := url.Parse(c.config.Address)
	if err != nil {
		return 0, nil, err
	}
	target, err := url.Parse(path)
	if err != nil {
		return 0, nil, err
	}
	base.Path, _ = url.JoinPath(base.Path, target.Path)
	base.RawQuery = target.RawQuery
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, base.String(), reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.config.APIKey != "" {
		req.Header.Set("X-API-KEY", c.config.APIKey)
	} else if c.csrf != "" {
		req.Header.Set("X-Csrf-Token", c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// The URL is the address's, which tells nothing more than the error.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = fmt.Errorf("%s request: %w", urlErr.Op, urlErr.Err)
		}
		return 0, nil, err
	}
	defer resp.Body.Close()
	for _, header := range []string{"X-Csrf-Token", "X-Updated-Csrf-Token"} {
		if token := resp.Header.Get(header); token != "" {
			c.csrf = token
		}
	}
	answer, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("HTTP %s: reading the answer: %w", resp.Status, err)
	}
	return resp.StatusCode, answer, nil
}

// login logs the user in: at UniFi OS's login, or at a self-hosted Network Application's, which
// answers UniFi OS's with an error of its own form, with meta.
func (c *Client) login(ctx context.Context) error {
	c.csrf = ""
	credentials := map[string]any{"username": c.config.Username, "password": c.config.Password}
	c.unifiOS = true
	status, answer, err := c.do(ctx, http.MethodPost, "/api/auth/login", credentials)
	if err == nil && status != http.StatusOK && selfHostedAnswer(answer) {
		c.unifiOS = false
		status, answer, err = c.do(ctx, http.MethodPost, "/api/login", credentials)
	}
	switch {
	case err != nil:
		return fmt.Errorf("logging in: %w", err)
	case status == http.StatusOK:
		c.loggedIn = true
		return nil
	case status == http.StatusBadRequest || status == http.StatusUnauthorized || status == http.StatusForbidden:
		// A self-hosted Network Application refuses with 400, UniFi OS with 403.
		return fmt.Errorf("logging in: HTTP %d: the username or the password is refused. A user with two-factor authentication can't log in here: use an API key, or a local user without it", status)
	}
	return fmt.Errorf("logging in: %w", c.refused(status, answer))
}

// selfHostedAnswer tells an answer of a self-hosted Network Application's API, which has meta.
func selfHostedAnswer(answer []byte) bool {
	var said struct {
		Meta *struct{} `json:"meta"`
	}
	return json.Unmarshal(answer, &said) == nil && said.Meta != nil
}

// Error is an answer of the API that isn't 200: its status, what UniFi said, in whichever of its
// forms, and the fields it refused, if it says.
type Error struct {
	Status  int
	Message string
	Fields  []string
	// What to do about it, where the client can tell.
	Hint string
}

func (e *Error) Error() string {
	text := fmt.Sprintf("HTTP %d", e.Status)
	switch {
	case e.Hint != "" && e.Message != "":
		return text + ": " + e.Message + ": " + e.Hint
	case e.Hint != "":
		return text + ": " + e.Hint
	case e.Message == "":
		return text + ": not an answer of the UniFi Network API"
	}
	message := e.Message
	if len(e.Fields) > 0 {
		message += " (" + strings.Join(e.Fields, ", ") + ")"
	}
	return text + ": " + message
}

// refused is the *Error of an answer, with what to do about a refused key, a site that isn't
// there, or too many requests.
func (c *Client) refused(status int, answer []byte) error {
	var said struct {
		Message string `json:"message"`
		Error   struct {
			Message string `json:"message"`
		} `json:"error"`
		Meta struct {
			Msg string `json:"msg"`
		} `json:"meta"`
		Details struct {
			InvalidFields []string `json:"invalid_fields"`
		} `json:"details"`
	}
	e := &Error{Status: status}
	if json.Unmarshal(answer, &said) == nil {
		e.Message = said.Message
		if e.Message == "" {
			e.Message = said.Error.Message
		}
		if e.Message == "" {
			e.Message = said.Meta.Msg
		}
		e.Fields = said.Details.InvalidFields
	}
	if len(e.Message) > 200 {
		e.Message = e.Message[:200]
	}
	switch {
	case status == http.StatusUnauthorized && c.config.APIKey != "":
		e.Message, e.Hint = "", "the API key is refused: create one in UniFi OS, Settings, Control Plane, Integrations"
	case status == http.StatusNotFound && c.config.APIKey != "":
		e.Message, e.Hint = "", fmt.Sprintf("not here: the site %q, or the address, is wrong. An API key is of UniFi OS alone: a self-hosted Network Application needs username and password", c.config.Site)
	case status == http.StatusNotFound:
		e.Message, e.Hint = "", fmt.Sprintf("not here: the site %q, or the address, is wrong", c.config.Site)
	case status == http.StatusTooManyRequests:
		e.Message, e.Hint = "", "too many requests, or logins: UniFi asks to wait"
	}
	return e
}
