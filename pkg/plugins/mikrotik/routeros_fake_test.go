package mikrotik

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/go-routeros/routeros/v3/proto"
)

// serveRouterOS serves the RouterOS API on a local port: it logs in anyone, and answers the other
// commands with the rows handle returns. It returns the address.
func serveRouterOS(t *testing.T, tlsConfig *tls.Config, handle func(command string) []map[string]string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r := bufio.NewReader(conn)
				w := proto.NewWriter(conn)
				for {
					words, err := readSentence(r)
					if err != nil {
						return
					}
					tag := ""
					for _, word := range words[1:] {
						if strings.HasPrefix(word, ".tag=") {
							tag = strings.TrimPrefix(word, ".tag=")
						}
					}
					reply := func(word string, pairs map[string]string) {
						w.BeginSentence()
						w.WriteWord(word)
						if tag != "" {
							w.WriteWord(".tag=" + tag)
						}
						for k, v := range pairs {
							w.WriteWord("=" + k + "=" + v)
						}
						w.EndSentence()
					}
					if words[0] != "/login" {
						for _, row := range handle(words[0]) {
							reply("!re", row)
						}
					}
					reply("!done", nil)
				}
			}()
		}
	}()
	return listener.Addr().String()
}

func readSentence(r *bufio.Reader) ([]string, error) {
	var words []string
	for {
		length, err := readLength(r)
		if err != nil {
			return nil, err
		}
		if length == 0 {
			if len(words) == 0 {
				return nil, errors.New("empty sentence")
			}
			return words, nil
		}
		word := make([]byte, length)
		if _, err := io.ReadFull(r, word); err != nil {
			return nil, err
		}
		words = append(words, string(word))
	}
}

func readLength(r *bufio.Reader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	var extra, length int
	switch {
	case b&0x80 == 0:
		return int(b), nil
	case b&0xC0 == 0x80:
		extra, length = 1, int(b&0x3F)
	case b&0xE0 == 0xC0:
		extra, length = 2, int(b&0x1F)
	case b&0xF0 == 0xE0:
		extra, length = 3, int(b&0x0F)
	default:
		extra = 4
	}
	for range extra {
		c, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		length = length<<8 | int(c)
	}
	return length, nil
}
