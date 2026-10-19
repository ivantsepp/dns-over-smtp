package inspect

import (
	"os"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const query = "V7UBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE="
const response = "V7WBgAABAAIAAAAAB2V4YW1wbGUDY29tAAABAAHADAABAAEAAAEsAARoFBeawAwAAQABAAABLAAErEKT8w=="
const requestID = "199fdc8b9f90dd76d04a4669a1e5497b"

func TestCapturedPackets(t *testing.T) {
	cases := []struct {
		name, input, kind, id string
		answers               int
	}{
		{"bare query", query, "DNS-QUERY", "", 0},
		{"wrapped base64", query[:16] + "\n\t" + query[16:], "DNS-QUERY", "", 0},
		{"query line", "DNS-QUERY: " + requestID + " " + query, "DNS-QUERY", requestID, 0},
		{"bare response", response, "DNS-RESPONSE", "", 2},
		{"response line", "550 5.0.0 DNS-RESPONSE: " + requestID + " " + response + " [NOERROR A=104.20.23.154]", "DNS-RESPONSE", requestID, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			messages, err := Decode([]byte(tc.input))
			if err != nil {
				t.Fatal(err)
			}
			if len(messages) != 1 {
				t.Fatalf("got %d messages", len(messages))
			}
			message := messages[0]
			m := message.DNS
			if message.Kind != tc.kind || message.RequestID != tc.id || m.Id != 22453 || len(m.Question) != 1 || m.Question[0].Name != "example.com." || m.Question[0].Qtype != dns.TypeA || len(m.Answer) != tc.answers {
				t.Fatalf("wrong decode: %+v\n%s", message, m)
			}
			if tc.answers > 0 {
				for i, ip := range []string{"104.20.23.154", "172.66.147.243"} {
					rr, ok := m.Answer[i].(*dns.A)
					if !ok || rr.A.String() != ip || rr.Hdr.Ttl != 300 {
						t.Fatalf("wrong record: %v", m.Answer[i])
					}
				}
			}
		})
	}
}

func TestWholeWiresharkConversation(t *testing.T) {
	raw, err := os.ReadFile("testdata/wireshark.txt")
	if err != nil {
		t.Fatal(err)
	}
	messages, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || messages[0].Kind != "DNS-QUERY" || messages[1].Kind != "DNS-RESPONSE" || messages[0].RequestID != messages[1].RequestID {
		t.Fatalf("wrong messages: %+v", messages)
	}
}

func TestWrappedMarkedCaptures(t *testing.T) {
	for i := 1; i < len(response); i++ {
		input := "DNS-QUERY: " + requestID + "\r\n" + query[:17] + "\r\n" + query[17:] + "\r\n.\r\n550 5.0.0 DNS-RESPONSE: " + requestID + "\r\n" + response[:i] + "\r\n\t" + response[i:] + " [NOERROR A=104.20.23.154]"
		messages, err := Decode([]byte(input))
		if err != nil {
			t.Fatalf("split %d: %v", i, err)
		}
		if len(messages) != 2 || messages[0].Kind != "DNS-QUERY" || len(messages[1].DNS.Answer) != 2 {
			t.Fatalf("wrong split decode: %+v", messages)
		}
	}
}

func TestSavedGmailQuery(t *testing.T) {
	raw, err := os.ReadFile("../protocol/testdata/gmail-wrapped.eml")
	if err != nil {
		t.Fatal(err)
	}
	messages, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || messages[0].Kind != "DNS-QUERY" || messages[0].RequestID != requestID || messages[0].DNS.Id != 22453 {
		t.Fatalf("wrong saved query: %+v", messages)
	}
}

func TestSavedBareQuery(t *testing.T) {
	for _, body := range []string{"A example.test", "\r\nexample.test\r\n\r\n-- \r\nSender"} {
		raw := "Subject: unrestricted\r\nContent-Type: text/plain\r\n\r\n" + body + "\r\n"
		messages, err := Decode([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if len(messages) != 1 || messages[0].Kind != "DNS-QUERY" || len(messages[0].RequestID) != 32 || messages[0].DNS.Question[0].Name != "example.test." || messages[0].DNS.Question[0].Qtype != dns.TypeA {
			t.Fatalf("wrong saved query: %+v", messages)
		}
	}
}

func TestSavedBounceRemainsStrict(t *testing.T) {
	diagnostic := "DNS-RESPONSE: " + requestID + " " + response
	raw := "Content-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; relay.test\r\n\r\nAction: failed\r\nStatus: 5.0.0\r\nDiagnostic-Code: smtp; 550 5.0.0 " + diagnostic + "\r\n\r\n"
	messages, err := Decode([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || len(messages[0].DNS.Answer) != 2 {
		t.Fatal("lost saved-bounce answer")
	}
	original := "Content-Type: multipart/report; boundary=b\r\n\r\n--b\r\nContent-Type: message/rfc822\r\n\r\nFrom: user@example.test\r\n\r\n550 " + diagnostic + "\r\n--b--\r\n"
	if _, err := Decode([]byte(original)); err == nil {
		t.Fatal("treated attached original as answer")
	}
}

func TestInvalidAndBoundedInput(t *testing.T) {
	line := "DNS-QUERY: " + requestID + " " + query + "\n"
	for _, input := range []string{
		"", "not base64!", "dGVzdA==", "DNS-QUERY: invalid " + query,
		"DNS-QUERY: " + requestID + " " + response,
		"DNS-RESPONSE: " + requestID + " " + query,
		line + "DNS-RESPONSE: malformed",
		strings.Repeat("A", MaxInputBytes+1),
		strings.Repeat("A", 100000),
		strings.Repeat(line, maxMessages+1),
	} {
		if _, err := Decode([]byte(input)); err == nil {
			t.Fatalf("accepted invalid input (length %d)", len(input))
		}
	}
}
