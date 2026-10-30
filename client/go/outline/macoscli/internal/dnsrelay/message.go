// Copyright 2026 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dnsrelay

import (
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"time"

	"localhost/client/go/outline/macoscli/internal/rules"

	"golang.org/x/net/dns/dnsmessage"
)

// maxChain bounds how many CNAME records are followed.
const maxChain = 16

// Classify returns the class of a DNS query from its question names: Bypass
// only if every question is a bypass name, VPNOnly if any is a vpn_only name,
// None otherwise. It also returns the first question name, for logs.
// A message that can't be parsed, or isn't a plain query, is None, so it goes
// through the tunnel untouched.
func Classify(query []byte, r *rules.Rules) (rules.Class, string) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil || h.Response || h.OpCode != 0 {
		return rules.None, ""
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) == 0 {
		return rules.None, ""
	}
	all := rules.Bypass
	for _, q := range qs {
		switch c, _ := r.Match(q.Name.String()); c {
		case rules.VPNOnly:
			return rules.VPNOnly, rules.Normalize(qs[0].Name.String())
		case rules.None:
			all = rules.None
		}
	}
	return all, rules.Normalize(qs[0].Name.String())
}

// Learned is an address that a DNS answer ties to a listed domain.
type Learned struct {
	Addr  netip.Addr
	Class rules.Class
	// Domain is the question name the answer is for.
	Domain string
	// TTL is the smallest TTL along the answer's CNAME chain (not clamped).
	TTL time.Duration
}

// Snoop extracts the addresses a DNS response gives for listed domains.
//
// For each question it follows the CNAME chain from the question name. The
// chain's class is the strongest class of any name in it, so a CNAME into a
// listed domain counts, and vpn_only wins. The TTL is the smallest along the
// chain. A and AAAA records are collected for every name in the chain.
// Responses that aren't successful, or can't be parsed, give nothing.
func Snoop(response []byte, r *rules.Rules) []Learned {
	var p dnsmessage.Parser
	h, err := p.Start(response)
	if err != nil || !h.Response || h.RCode != dnsmessage.RCodeSuccess {
		return nil
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return nil
	}
	answers, err := p.AllAnswers()
	if err != nil {
		return nil
	}

	var out []Learned
	for _, q := range qs {
		if q.Class != dnsmessage.ClassINET {
			continue
		}
		start := rules.Normalize(q.Name.String())
		class, _ := r.Match(start)
		chainTTL := uint32(math.MaxUint32)
		inChain := map[string]bool{start: true}
		for name, hops := start, 0; hops < maxChain; hops++ {
			next := ""
			for _, a := range answers {
				if a.Header.Type != dnsmessage.TypeCNAME || rules.Normalize(a.Header.Name.String()) != name {
					continue
				}
				next = rules.Normalize(a.Body.(*dnsmessage.CNAMEResource).CNAME.String())
				chainTTL = min(chainTTL, a.Header.TTL)
				break
			}
			if next == "" || inChain[next] {
				break
			}
			inChain[next] = true
			if c, _ := r.Match(next); c > class {
				class = c
			}
			name = next
		}
		if class == rules.None {
			continue
		}
		for _, a := range answers {
			if !inChain[rules.Normalize(a.Header.Name.String())] {
				continue
			}
			var addr netip.Addr
			switch body := a.Body.(type) {
			case *dnsmessage.AResource:
				addr = netip.AddrFrom4(body.A)
			case *dnsmessage.AAAAResource:
				addr = netip.AddrFrom16(body.AAAA).Unmap()
			default:
				continue
			}
			ttl := min(chainTTL, a.Header.TTL)
			out = append(out, Learned{Addr: addr, Class: class, Domain: start, TTL: time.Duration(ttl) * time.Second})
		}
	}
	return out
}

// messageID returns the ID of a DNS message.
func messageID(msg []byte) (uint16, bool) {
	if len(msg) < 12 {
		return 0, false
	}
	return binary.BigEndian.Uint16(msg), true
}

// isResponseTo reports whether reply is a response with the query's ID.
func isResponseTo(reply, query []byte) bool {
	qid, ok1 := messageID(query)
	rid, ok2 := messageID(reply)
	return ok1 && ok2 && qid == rid && reply[2]&0x80 != 0
}

// rcode returns the response code of a DNS message.
func rcode(msg []byte) dnsmessage.RCode {
	if len(msg) < 4 {
		return dnsmessage.RCodeFormatError
	}
	return dnsmessage.RCode(msg[3] & 0x0f)
}

// truncated reports whether a DNS message has the TC bit set.
func truncated(msg []byte) bool {
	return len(msg) >= 3 && msg[2]&0x02 != 0
}

// NewQuery builds a recursive query for name and type.
func NewQuery(id uint16, name string, qtype dnsmessage.Type) ([]byte, error) {
	if name == "" || name[len(name)-1] != '.' {
		name += "."
	}
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// Framer splits a DNS-over-TCP byte stream (RFC 1035 4.2.2: each message is
// preceded by its 2-byte length) into messages.
type Framer struct {
	buf []byte
}

// errEmptyFrame is returned for a zero-length message.
var errEmptyFrame = errors.New("zero-length DNS message")

// Push adds bytes from the stream and returns the messages now complete. A
// length prefix or message may be split across calls, and one call may
// complete several messages.
func (f *Framer) Push(p []byte) ([][]byte, error) {
	f.buf = append(f.buf, p...)
	var msgs [][]byte
	for len(f.buf) >= 2 {
		n := int(binary.BigEndian.Uint16(f.buf))
		if n == 0 {
			return msgs, errEmptyFrame
		}
		if len(f.buf) < 2+n {
			break
		}
		msgs = append(msgs, append([]byte(nil), f.buf[2:2+n]...))
		f.buf = f.buf[2+n:]
	}
	if len(f.buf) == 0 {
		f.buf = nil
	}
	return msgs, nil
}

// frame prefixes a DNS message with its 2-byte length.
func frame(msg []byte) []byte {
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg)))
	copy(out[2:], msg)
	return out
}
