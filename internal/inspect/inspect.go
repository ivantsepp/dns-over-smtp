// Package inspect decodes captures offline. It is not part of the mail transport.
package inspect

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"

	"dns-over-smtp/internal/protocol"
	"github.com/miekg/dns"
)

const MaxInputBytes = 1024 * 1024
const maxMessages = 128

var marker = regexp.MustCompile(`(?m)(?:^|[ \t])DNS-(QUERY|RESPONSE):\s+([a-f0-9]{32})\s+`)

type Message struct {
	Kind      string
	RequestID string
	DNS       *dns.Msg
}

// Decode accepts bare base64, marked lines, SMTP conversations or saved mail.
// Saved mail uses MIME query/DSN parsers, never raw HTML or attached messages.
func Decode(raw []byte) ([]Message, error) {
	if len(raw) > MaxInputBytes {
		return nil, errors.New("decoder input exceeds 1 MiB")
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil, errors.New("empty input: paste base64 or DNS-QUERY/DNS-RESPONSE lines")
	}
	if m, err := mail.ReadMessage(bytes.NewReader(raw)); err == nil &&
		(m.Header.Get("Content-Type") != "" || m.Header.Get("From") != "" || m.Header.Get("Subject") != "") {
		answer, err := protocol.ParseBounce(raw, "")
		if err == nil {
			return []Message{{Kind: "DNS-RESPONSE", DNS: answer}}, nil
		}
		if !errors.Is(err, protocol.ErrNoResponse) {
			return nil, fmt.Errorf("decode saved bounce: %w", err)
		}
		query, id, err := protocol.ParseQuery(raw)
		if err != nil {
			return nil, fmt.Errorf("no valid DNS query or bounce in saved email: %w", err)
		}
		return []Message{{Kind: "DNS-QUERY", RequestID: id, DNS: query}}, nil
	}
	matches := marker.FindAllStringSubmatchIndex(text, maxMessages+1)
	if len(matches) > maxMessages {
		return nil, errors.New("decoder input contains more than 128 messages")
	}
	markers := strings.Count(text, "DNS-QUERY:") + strings.Count(text, "DNS-RESPONSE:")
	if markers != len(matches) {
		return nil, errors.New("malformed DNS marker: expected a 32-character hex ID followed by base64")
	}
	if len(matches) == 0 {
		payload := strings.Join(strings.Fields(text), "")
		m, err := decodePacket(payload)
		if err != nil {
			return nil, err
		}
		return []Message{{Kind: kind(m), DNS: m}}, nil
	}
	result := make([]Message, 0, len(matches))
	for i, match := range matches {
		end := len(text)
		if i+1 < len(matches) {
			end = matches[i+1][0]
		}
		m, err := protocol.DecodePayload(text[match[1]:end], dns.MaxMsgSize)
		if err != nil {
			return nil, fmt.Errorf("message %d: %w", i+1, err)
		}
		label := "DNS-" + text[match[2]:match[3]]
		if label != kind(m) {
			return nil, fmt.Errorf("message %d: %s marker disagrees with DNS response flag", i+1, label)
		}
		result = append(result, Message{Kind: label, RequestID: text[match[4]:match[5]], DNS: m})
	}
	return result, nil
}

func decodePacket(payload string) (*dns.Msg, error) {
	if len(payload) > base64.StdEncoding.EncodedLen(dns.MaxMsgSize) {
		return nil, errors.New("base64 payload exceeds the maximum DNS packet size")
	}
	wire, err := base64.StdEncoding.Strict().DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	if len(wire) > dns.MaxMsgSize {
		return nil, errors.New("DNS packet exceeds 65535 bytes")
	}
	m := new(dns.Msg)
	if err := m.Unpack(wire); err != nil {
		return nil, fmt.Errorf("invalid DNS packet: %w", err)
	}
	return m, nil
}

func kind(m *dns.Msg) string {
	if m.Response {
		return "DNS-RESPONSE"
	}
	return "DNS-QUERY"
}
