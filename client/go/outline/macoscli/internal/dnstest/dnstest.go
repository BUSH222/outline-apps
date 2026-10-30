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

// Package dnstest builds DNS messages for tests.
package dnstest

import (
	"encoding/binary"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// RR is an answer record: a CNAME if CNAME is set, else an A or AAAA record
// for Addr.
type RR struct {
	Name  string
	CNAME string
	Addr  string
	TTL   uint32
}

// Query builds a query with one question per name.
func Query(id uint16, qtype dnsmessage.Type, names ...string) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	must(b.StartQuestions())
	for _, n := range names {
		must(b.Question(dnsmessage.Question{Name: name(n), Type: qtype, Class: dnsmessage.ClassINET}))
	}
	msg, err := b.Finish()
	must(err)
	return msg
}

// Options change a response's header.
type Options struct {
	RCode     dnsmessage.RCode
	Truncated bool
}

// Response builds a response to a query for qname with the given answers.
func Response(id uint16, qname string, opts Options, answers ...RR) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: id, Response: true, RecursionDesired: true, RecursionAvailable: true,
		RCode: opts.RCode, Truncated: opts.Truncated,
	})
	must(b.StartQuestions())
	must(b.Question(dnsmessage.Question{Name: name(qname), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}))
	must(b.StartAnswers())
	for _, rr := range answers {
		h := dnsmessage.ResourceHeader{Name: name(rr.Name), Class: dnsmessage.ClassINET, TTL: rr.TTL}
		switch {
		case rr.CNAME != "":
			must(b.CNAMEResource(h, dnsmessage.CNAMEResource{CNAME: name(rr.CNAME)}))
		default:
			addr := netip.MustParseAddr(rr.Addr)
			if addr.Is4() {
				must(b.AResource(h, dnsmessage.AResource{A: addr.As4()}))
			} else {
				must(b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: addr.As16()}))
			}
		}
	}
	msg, err := b.Finish()
	must(err)
	return msg
}

// ReplyTo builds a response to query (same ID and first question name).
func ReplyTo(query []byte, opts Options, answers ...RR) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	must(err)
	q, err := p.Question()
	must(err)
	return Response(h.ID, q.Name.String(), opts, answers...)
}

// QuestionName returns the first question name of a message, without the
// trailing dot.
func QuestionName(msg []byte) string {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return ""
	}
	q, err := p.Question()
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(q.Name.String(), ".")
}

// ID returns a message's ID.
func ID(msg []byte) uint16 {
	return binary.BigEndian.Uint16(msg)
}

// Frame prefixes a message with its 2-byte length, as on TCP.
func Frame(msg []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...)
}

func name(s string) dnsmessage.Name {
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return dnsmessage.MustNewName(s)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
