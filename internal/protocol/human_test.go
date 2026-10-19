package protocol

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestRequestResponseFormat(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	wire, err := EncodeQuery(q, testID)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		body  string
		human bool
	}{
		{"A example.test", true},
		{"example.test", true},
		{"a example.test\r\nDNS-QUERY: " + testID + " invalid", true},
		{"DNS-QUERY: A example.test", true},
		{"preamble\r\nDNS-QUERY:\r\nA example.test", true},
		{"DNS-QUERY: A\r\nexample.test", true},
		{wire, false},
	} {
		for _, encoded := range []bool{false, true} {
			raw := email(tc.body)
			if encoded {
				raw = []byte("Content-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte(tc.body)))
			}
			request, err := ParseRequest(raw)
			if err != nil {
				t.Fatal(err)
			}
			if request.HumanReadable != tc.human || request.Query.Question[0] != q.Question[0] || !validID(request.ID) {
				t.Fatalf("wrong request format for %q (MIME encoded=%v): %+v", tc.body, encoded, request)
			}
			if !tc.human && (request.ID != testID || request.Query.Id != q.Id) {
				t.Fatal("lost machine correlation")
			}
		}
	}
}

func TestHumanResponseRecordsAndStatus(t *testing.T) {
	m := answer()
	for _, text := range []string{
		"example.test. 60 IN CNAME target.test.",
		"target.test. 60 IN A 192.0.2.43",
	} {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		m.Answer = append(m.Answer, rr)
	}
	soa, err := dns.NewRR("example.test. 60 IN SOA ns.example.test. hostmaster.example.test. 1 2 3 4 5")
	if err != nil {
		t.Fatal(err)
	}
	m.Ns = []dns.RR{soa}
	m.Extra = []dns.RR{&dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}}
	text, err := FormatHumanResponse(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"DNS answer: example.test. A; status=NOERROR", "A 192.0.2.42", "CNAME target.test.", "A 192.0.2.43", "authority: example.test. 60 IN SOA"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, "OPT") || strings.Contains(text, "truncated") {
		t.Fatalf("unexpected metadata or truncation: %s", text)
	}
	for _, rcode := range []int{dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeServerFailure, dns.RcodeRefused, 4095} {
		m.Answer, m.Ns, m.Extra = nil, nil, nil
		m.Rcode = rcode
		text, err := FormatHumanResponse(m)
		if err != nil {
			t.Fatal(err)
		}
		want := dns.RcodeToString[rcode]
		if rcode == 4095 {
			want = "RCODE4095"
		}
		if !strings.Contains(text, "status="+want+"; no answers") {
			t.Fatalf("lost negative or empty result: %s", text)
		}
	}
}

func TestHumanResponseBoundsAndEscaping(t *testing.T) {
	m := answer()
	for i := 0; i < 50; i++ {
		m.Answer = append(m.Answer, m.Answer[0])
	}
	text, err := FormatHumanResponse(m)
	if err != nil {
		t.Fatal(err)
	}
	if len("550 5.0.0 "+text+"\r\n") > 512 || !strings.HasSuffix(text, "; [truncated]") || !strings.Contains(text, "A 192.0.2.42") {
		t.Fatalf("unbounded or unmarked partial response: %q", text)
	}
	if m.Truncated || len(m.Answer) != 51 {
		t.Fatal("mutated caller's message")
	}
	m = answer()
	m.Truncated = true
	text, err = FormatHumanResponse(m)
	if err != nil || !strings.HasSuffix(text, "; [truncated]") {
		t.Fatalf("lost upstream truncation: %q %v", text, err)
	}
	m.Truncated = false
	m.Question[0].Name = "bad\r\n\x1b\x7f\xff.test."
	m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: "bad\r\n.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"keep  spaces\r\n\x00\x1b\xff"}}}
	text, err = FormatHumanResponse(m)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(text); i++ {
		if text[i] < ' ' || text[i] > '~' {
			t.Fatalf("unsafe byte in SMTP diagnostic: %q", text)
		}
	}
	if !strings.Contains(text, "keep  spaces") {
		t.Fatalf("changed TXT whitespace: %q", text)
	}
	m.Question[0].Name = "example.test."
	m.Answer[0].(*dns.TXT).Txt = []string{strings.Repeat("x", 1000)}
	text, err = FormatHumanResponse(m)
	if err != nil || !strings.HasSuffix(text, "; [truncated]") || strings.Contains(text, "xxxxx") {
		t.Fatalf("partially rendered oversized record: %q %v", text, err)
	}
}

func TestInvalidHumanResponse(t *testing.T) {
	for _, m := range []*dns.Msg{nil, new(dns.Msg), {MsgHdr: dns.MsgHdr{Response: true}}} {
		if _, err := FormatHumanResponse(m); err == nil {
			t.Fatal("accepted invalid response")
		}
	}
	m := answer()
	m.Question[0].Name = strings.Repeat("\\001", 255) + "."
	if _, err := FormatHumanResponse(m); err == nil {
		t.Fatal("accepted a question exceeding the SMTP budget")
	}
}
