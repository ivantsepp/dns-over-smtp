package protocol

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestBareQueryBodies(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		qtype      uint16
	}{
		{"explicit type", "A example.test", dns.TypeA},
		{"default A", "example.test", dns.TypeA},
		{"trailing dot", "example.test.", dns.TypeA},
		{"lowercase type", "aaaa example.test", dns.TypeAAAA},
		{"MX", "MX example.test", dns.TypeMX},
		{"TXT", "TXT example.test", dns.TypeTXT},
		{"CAA", "CAA example.test", dns.TypeCAA},
		{"URI", "URI example.test", dns.TypeURI},
		{"signature", "\r\n\t\r\n A\t example.test \r\n\r\n-- \r\nExample Sender\r\nhttps://sender.test", dns.TypeA},
		{"domain signature", "\nexample.test\n\nThanks!\nother.test", dns.TypeA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, id, err := ParseQuery(email(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if !validID(id) || len(q.Question) != 1 || q.Question[0].Name != "example.test." || q.Question[0].Qtype != tc.qtype || q.Question[0].Qclass != dns.ClassINET {
				t.Fatalf("wrong manual query: %s %s", id, q)
			}
		})
	}
}

func TestBareQueryWinsOverLaterMarkers(t *testing.T) {
	for _, firstLine := range []string{"A example.test", "example.test"} {
		for _, signature := range []string{
			"DNS-QUERY: A other.test",
			"DNS-QUERY: badid invalid",
			"DNS-QUERY: A other.test\r\nDNS-QUERY: A third.test",
			"DNS-QUERY: " + capturedID + "\r\n" + capturedQuery,
		} {
			q, _, err := ParseQuery(email(firstLine + "\r\n\r\n-- \r\n" + signature))
			if err != nil {
				t.Fatalf("signature changed bare-query parsing: %v", err)
			}
			if q.Question[0].Name != "example.test." || q.Question[0].Qtype != dns.TypeA {
				t.Fatalf("signature overrode first-line query: %s", q)
			}
		}
	}
}

func TestOrdinaryRecordTypes(t *testing.T) {
	for _, qtype := range []uint16{dns.TypeCAA, dns.TypeURI, dns.TypeRESINFO, dns.TypeTA, dns.TypeDLV} {
		q := new(dns.Msg)
		q.SetQuestion("example.test.", qtype)
		body, err := EncodeQuery(q, testID)
		if err != nil {
			t.Fatalf("ordinary type %d rejected: %v", qtype, err)
		}
		for _, input := range []string{body, "DNS-QUERY: " + dns.TypeToString[qtype] + " example.test"} {
			parsed, _, err := ParseQuery(email(input))
			if err != nil {
				t.Fatalf("type %d failed to parse: %v", qtype, err)
			}
			if parsed.Question[0] != q.Question[0] {
				t.Fatalf("type %d changed question: %s", qtype, parsed)
			}
		}
	}
	for _, qtype := range []uint16{0, dns.TypeOPT, dns.TypeTKEY, dns.TypeTSIG, dns.TypeIXFR, dns.TypeAXFR, dns.TypeMAILA, dns.TypeMAILB, dns.TypeANY, dns.TypeReserved} {
		q := new(dns.Msg)
		q.SetQuestion("example.test.", qtype)
		if err := ValidateQuery(q); err == nil {
			t.Fatalf("accepted meta, transfer or reserved type %d", qtype)
		}
	}
}

func TestTaggedQueryWithPreamble(t *testing.T) {
	q, _, err := ParseQuery(email("Please look this up:\r\nDNS-QUERY: A example.test"))
	if err != nil {
		t.Fatal(err)
	}
	if q.Question[0].Name != "example.test." || q.Question[0].Qtype != dns.TypeA {
		t.Fatalf("wrong legacy query: %s", q)
	}
}

func TestBareQueryMIME(t *testing.T) {
	const body = "MX example.test"
	for name, raw := range map[string]string{
		"unrestricted subject": "Subject: TXT ignored.test\r\n\r\n" + body,
		"base64":               "Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte(body)),
		"quoted-printable":     "Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nMX example.=\r\ntest",
		"HTML alternative":     "Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\n" + body + "\r\n--b\r\nContent-Type: text/html\r\n\r\n<p>A ignored.test</p>\r\n--b--\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			q, _, err := ParseQuery([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			if q.Question[0].Name != "example.test." || q.Question[0].Qtype != dns.TypeMX {
				t.Fatalf("wrong MIME query: %s", q)
			}
		})
	}
}

func TestInvalidBareQueries(t *testing.T) {
	for _, body := range []string{
		"", "\r\n\t", "hello", "Thanks.", ".", "A", "A\nexample.test",
		"Hello\nA example.test", "A example.test extra", "UNKNOWN example.test",
		"AXFR example.test", "IXFR example.test", "ANY example.test", "OPT example.test", "TKEY example.test", "TSIG example.test",
		"https://example.test", "person@example.test", "bad..example.test", "A bad..example.test",
		strings.Repeat("a", 64) + ".test", "A " + strings.Repeat("a", 64) + ".test",
	} {
		if _, _, err := ParseQuery(email(body)); err == nil {
			t.Fatalf("accepted invalid bare body %q", body)
		}
	}
	for name, raw := range map[string]string{
		"subject only":  "Subject: A example.test\r\n\r\n",
		"HTML only":     "Content-Type: text/html\r\n\r\nA example.test",
		"attached mail": "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: message/rfc822\r\n\r\nSubject: DNS\r\n\r\nA example.test\r\n--b--\r\n",
		"split query":   "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nA\r\n--b\r\nContent-Type: text/plain\r\n\r\nexample.test\r\n--b--\r\n",
		"two bodies":    "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nA example.test\r\n--b\r\nContent-Type: text/plain\r\n\r\nAAAA other.test\r\n--b--\r\n",
		"mixed formats": "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nA example.test\r\n--b\r\nContent-Type: text/plain\r\n\r\nDNS-QUERY: A other.test\r\n--b--\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseQuery([]byte(raw)); err == nil {
				t.Fatal("accepted query outside a single plain-text body")
			}
		})
	}
}
