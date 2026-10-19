package protocol

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const testID = "0123456789abcdef0123456789abcdef"

func email(body string) []byte {
	return []byte("Subject: DNS\r\nContent-Type: text/plain\r\n\r\n" + body + "\r\n")
}

func answer() *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	m := new(dns.Msg)
	m.SetReply(q)
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.42")}}
	return m
}

func dsn(diagnostic string) []byte {
	return []byte("Content-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; relay.test\r\n\r\nFinal-Recipient: rfc822; dns@localhost\r\nAction: failed\r\nStatus: 5.0.0\r\nDiagnostic-Code: smtp; 550 5.0.0 " + diagnostic + "\r\n\r\n")
}

func TestQueryMIME(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeAAAA)
	body, err := EncodeQuery(q, testID)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"plain":            email(body),
		"human":            email("DNS-QUERY: AAAA example.test"),
		"base64":           []byte("Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte(body))),
		"quoted-printable": []byte("Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nDNS-QUERY: AAAA example.test"),
		"multipart":        []byte("Content-Type: multipart/alternative; boundary=test\r\n\r\n--test\r\nContent-Type: text/plain\r\n\r\n" + body + "\r\n--test\r\nContent-Type: text/html\r\n\r\n<p>other content</p>\r\n--test--\r\n"),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			parsed, id, err := ParseQuery(raw)
			if err != nil {
				t.Fatal(err)
			}
			if !validID(id) || parsed.Question[0] != q.Question[0] {
				t.Fatalf("wrong query: %v %s", parsed, id)
			}
			if name != "human" && name != "quoted-printable" && (id != testID || parsed.Id != q.Id) {
				t.Fatal("wire ID changed")
			}
		})
	}
}

func TestInvalidQueries(t *testing.T) {
	for _, body := range []string{"hello", "DNS-QUERY:", "DNS-QUERY: AXFR example.test", "DNS-QUERY: ANY example.test", "DNS-QUERY: OPT example.test", "DNS-QUERY: TKEY example.test", "DNS-QUERY: TSIG example.test", "DNS-QUERY: A example.test\r\nDNS-QUERY: A other.test", "DNS-QUERY:\r\nDNS-QUERY: A example.test", "DNS-QUERY: badid invalid"} {
		if _, _, err := ParseQuery(email(body)); err == nil {
			t.Fatalf("accepted %q", body)
		}
	}
	if _, _, err := ParseQuery(make([]byte, MaxMailBytes+1)); err == nil {
		t.Fatal("accepted oversized email")
	}
	q := new(dns.Msg)
	if _, err := EncodeQuery(q, testID); err == nil {
		t.Fatal("accepted no questions")
	}
	q.SetQuestion("example.test.", dns.TypeA)
	q.Question = append(q.Question, q.Question[0])
	if _, err := EncodeQuery(q, testID); err == nil {
		t.Fatal("accepted multiple questions")
	}
}

func TestBounceCorrelationAndFolding(t *testing.T) {
	m := answer()
	payload, err := EncodeResponse(m, testID)
	if err != nil {
		t.Fatal(err)
	}
	folded := strings.Replace(payload, testID+" ", testID+"\r\n\t", 1)
	for _, diagnostic := range []string{payload, folded} {
		parsed, err := ParseBounce(dsn(diagnostic), testID)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateResponse(parsed, &dns.Msg{MsgHdr: dns.MsgHdr{Id: m.Id}, Question: m.Question}); err != nil {
			t.Fatal(err)
		}
		if len(parsed.Answer) != 1 {
			t.Fatal("lost answer")
		}
	}
	if _, err := ParseBounce(dsn(payload), "ffffffffffffffffffffffffffffffff"); !errors.Is(err, ErrNoResponse) {
		t.Fatalf("matched wrong ID: %v", err)
	}
	if _, err := ParseBounce(email("550 5.0.0 "+payload), testID); !errors.Is(err, ErrNoResponse) {
		t.Fatal("parsed ordinary text as DSN")
	}
	original := "Content-Type: multipart/report; boundary=b\r\n\r\n--b\r\nContent-Type: message/rfc822\r\n\r\nContent-Type: message/delivery-status\r\n\r\nAction: failed\r\nDiagnostic-Code: smtp; 550 " + payload + "\r\n\r\n--b--\r\n"
	if _, err := ParseBounce([]byte(original), testID); !errors.Is(err, ErrNoResponse) {
		t.Fatal("parsed attached original message")
	}
	if _, err := ParseResponse("DNS-RESPONSE: "+testID+" dGVzdA==", testID); err == nil {
		t.Fatal("accepted invalid DNS bytes")
	}
	bad := m.Copy()
	bad.Question[0].Name = "wrong.test."
	if err := ValidateResponse(bad, m); err == nil {
		t.Fatal("accepted wrong DNS question")
	}
	bad = m.Copy()
	bad.Id++
	if err := ValidateResponse(bad, m); err == nil {
		t.Fatal("accepted wrong DNS ID")
	}
}

func TestSingleLineBoundAndNegativeResponse(t *testing.T) {
	m := answer()
	for i := 0; i < 50; i++ {
		m.Answer = append(m.Answer, m.Answer[0])
	}
	payload, err := EncodeResponse(m, testID)
	if err != nil {
		t.Fatal(err)
	}
	if n := len("550 5.0.0 " + payload + "\r\n"); n > 512 {
		t.Fatalf("reply has %d bytes", n)
	}
	parsed, err := ParseResponse(payload, testID)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Truncated {
		t.Fatal("missing TC flag")
	}
	if m.Truncated || len(m.Answer) != 51 {
		t.Fatal("mutated caller's message")
	}
	m = answer()
	m.Answer = nil
	m.Rcode = dns.RcodeNameError
	payload, err = EncodeResponse(m, testID)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = ParseBounce(dsn(payload), testID)
	if err != nil || parsed.Rcode != dns.RcodeNameError {
		t.Fatalf("NXDOMAIN lost: %v", err)
	}
}

func TestResponseOversizeRejected(t *testing.T) {
	_, err := ParseResponse(fmt.Sprintf("DNS-RESPONSE: %s %s", testID, strings.Repeat("a", 1000)), testID)
	if err == nil {
		t.Fatal("oversized response accepted")
	}
}
