package protocol

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const capturedQuery = "V7UBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE="
const capturedID = "199fdc8b9f90dd76d04a4669a1e5497b"

func TestGmailWrappedMIMEQuery(t *testing.T) {
	raw, err := os.ReadFile("testdata/gmail-wrapped.eml")
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{string(raw), strings.ReplaceAll(string(raw), "\n", "\r\n")} {
		m, id, err := ParseQuery([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		if id != capturedID || m.Id != 22453 || len(m.Question) != 1 || m.Question[0].Name != "example.com." || m.Question[0].Qtype != dns.TypeA {
			t.Fatalf("wrong query: %s %s", id, m)
		}
	}
}

func TestQueryPayloadWhitespace(t *testing.T) {
	for i := 1; i < len(capturedQuery); i++ {
		body := "DNS-QUERY: " + capturedID + "\r\n" + capturedQuery[:i] + "\r\n\t" + capturedQuery[i:] + "\r\nRegards\r\nSender"
		q, id, err := ParseQuery(email(body))
		if err != nil || id != capturedID || q.Id != 22453 {
			t.Fatalf("split %d: %v", i, err)
		}
	}
	for _, body := range []string{
		"DNS-QUERY:\n" + capturedID + "\n" + strings.Join(strings.Split(capturedQuery, ""), " \t\n"),
		"DNS-QUERY: A\nexample.com",
		"DNS-QUERY:\nA example.com",
	} {
		if _, _, err := ParseQuery(email(body)); err != nil {
			t.Fatal(err)
		}
	}
	body := "DNS-QUERY: " + capturedID + "\n" + capturedQuery
	outerBase64 := "Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte(body))
	quoted := "Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nDNS-QUERY: " + capturedID + "\r\n" + capturedQuery[:17] + "=\r\n" + strings.ReplaceAll(capturedQuery[17:], "=", "=3D")
	for _, raw := range []string{outerBase64, quoted} {
		if _, _, err := ParseQuery([]byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEncodedQueryHasShortLines(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion(strings.Repeat("a", 60)+"."+strings.Repeat("b", 60)+".example.", dns.TypeA)
	body, err := EncodeQuery(q, testID)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(body, "\r\n")
	if len(lines) < 3 || lines[0] != "DNS-QUERY: "+testID {
		t.Fatalf("unexpected framing: %q", body)
	}
	for _, line := range lines {
		if len(line) > 64 {
			t.Fatalf("line has %d columns", len(line))
		}
	}
	parsed, id, err := ParseQuery(email(body))
	if err != nil || id != testID || parsed.Question[0] != q.Question[0] {
		t.Fatalf("round trip failed: %v", err)
	}
}

func TestCannotJoinPayloadAcrossMIMEParts(t *testing.T) {
	for _, secondType := range []string{"text/html", "text/plain"} {
		raw := "Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nDNS-QUERY: " + capturedID + "\r\n" + capturedQuery[:20] + "\r\n--b\r\nContent-Type: " + secondType + "\r\n\r\n" + capturedQuery[20:] + "\r\n--b--\r\n"
		if _, _, err := ParseQuery([]byte(raw)); err == nil {
			t.Fatalf("joined payload across %s part", secondType)
		}
	}
	if _, _, err := ParseQuery(email("DNS-QUERY: " + capturedID + "\n" + capturedQuery + "\nDNS-QUERY: A other.example")); err == nil {
		t.Fatal("accepted duplicate marker")
	}
}

func TestResponsePayloadFolding(t *testing.T) {
	m := answer()
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	payload := base64.StdEncoding.EncodeToString(wire)
	for i := 1; i < len(payload); i++ {
		diagnostic := "DNS-RESPONSE: " + testID + " " + payload[:i] + "\r\n\t" + payload[i:] + " [NOERROR]"
		parsed, err := ParseResponse(diagnostic, testID)
		if err != nil || parsed.Id != m.Id || len(parsed.Answer) != 1 {
			t.Fatalf("direct split %d: %v", i, err)
		}
		parsed, err = ParseBounce(dsn(diagnostic), testID)
		if err != nil || parsed.Id != m.Id || len(parsed.Answer) != 1 {
			t.Fatalf("DSN split %d: %v", i, err)
		}
	}
}

func TestPayloadLimitsAndTrailingBytes(t *testing.T) {
	wire, err := base64.StdEncoding.DecodeString(capturedQuery)
	if err != nil {
		t.Fatal(err)
	}
	junk := base64.StdEncoding.EncodeToString(append(wire, 0, 0, 0))
	for _, payload := range []string{junk, "invalid!", strings.Repeat("A", base64.StdEncoding.EncodedLen(MaxQueryBytes)+4)} {
		if _, err := DecodePayload(payload, MaxQueryBytes); err == nil {
			t.Fatal("accepted invalid/oversized payload")
		}
	}
	if _, err := DecodePayload(capturedQuery, 0); err == nil {
		t.Fatal("accepted invalid limit")
	}
	if _, err := DecodePayload(capturedQuery[:16], MaxQueryBytes); err == nil {
		t.Fatal("accepted header declaring a missing question")
	}
	if _, _, err := ParseQuery(email("DNS-QUERY:\nA example.com extra")); err == nil {
		t.Fatal("accepted extra human-query tokens")
	}
}
