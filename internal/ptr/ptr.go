// Package ptr has the question for the name of an address, the PTR record of its reverse name,
// and what is read of its answer: what LLMNR and the reverse DNS share.
package ptr

import (
	"errors"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/miguelangel-nubla/ipv6disc/pkg/mdns"
)

// Query is a question for the PTR record of the reverse name of addr, alone. recursion asks a
// DNS server to look for it elsewhere too, as a resolver does.
func Query(id uint16, addr netip.Addr, recursion bool) ([]byte, error) {
	name, err := dnsmessage.NewName(mdns.ReverseName(addr))
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: recursion})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// Answer is what is taken of a message.
type Answer struct {
	ID       uint16
	Response bool
	RCode    dnsmessage.RCode
	// The name its one question asks the PTR record of, lower case: "" when it has another
	// question, or more than one.
	Question string
	// What the PTR records of that name, among its answers, point to, as they have it.
	Names []string
}

// errQuestion is of a message with no question, or several.
var errQuestion = errors.New("not one question")

// Parse reads the answer to a Query. One that can't be read to the end of its answers is an
// error, with nothing taken of it.
func Parse(packet []byte) (Answer, error) {
	var p dnsmessage.Parser
	header, err := p.Start(packet)
	if err != nil {
		return Answer{}, err
	}
	a := Answer{ID: header.ID, Response: header.Response, RCode: header.RCode}
	questions, err := p.AllQuestions()
	if err != nil {
		return Answer{}, err
	}
	if len(questions) != 1 {
		return Answer{}, errQuestion
	}
	if q := questions[0]; q.Type == dnsmessage.TypePTR && q.Class == dnsmessage.ClassINET {
		a.Question = strings.ToLower(q.Name.String())
	}
	for {
		h, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return a, nil
		}
		if err != nil {
			return Answer{}, err
		}
		if h.Type != dnsmessage.TypePTR || h.Class != dnsmessage.ClassINET || a.Question == "" || strings.ToLower(h.Name.String()) != a.Question || len(a.Names) >= 8 {
			if err := p.SkipAnswer(); err != nil {
				return Answer{}, err
			}
			continue
		}
		r, err := p.PTRResource()
		if err != nil {
			return Answer{}, err
		}
		a.Names = append(a.Names, r.PTR.String())
	}
}

// Name is the name an answer gives the host at addr: what the first PTR record of its reverse
// name points to, in a response without an error to the question for it.
func (a Answer) Name(addr netip.Addr) (string, bool) {
	if !a.Response || a.RCode != dnsmessage.RCodeSuccess || len(a.Names) == 0 || a.Question != mdns.ReverseName(addr) {
		return "", false
	}
	return a.Names[0], true
}

// Asks tells whether the answer is to the question for the name of addr, whatever it answers.
func (a Answer) Asks(addr netip.Addr) bool {
	return a.Question != "" && a.Question == mdns.ReverseName(addr)
}

// Response is the answer a responder gives the Query with that ID for the name of addr: its
// question again, and a PTR record of its reverse name for each of names, or an error. It is for
// the tests of what asks.
func Response(id uint16, addr netip.Addr, rcode dnsmessage.RCode, names ...string) ([]byte, error) {
	reverse, err := dnsmessage.NewName(mdns.ReverseName(addr))
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: true, RCode: rcode})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: reverse, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	for _, name := range names {
		target, err := dnsmessage.NewName(name)
		if err != nil {
			return nil, err
		}
		if err := b.PTRResource(dnsmessage.ResourceHeader{Name: reverse, Class: dnsmessage.ClassINET, TTL: 30}, dnsmessage.PTRResource{PTR: target}); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}
