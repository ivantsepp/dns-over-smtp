package protocol

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// DecodePayload reads one complete DNS packet from whitespace-separated base64
// chunks. Stop at packet completion, before an SMTP line, summary or signature.
// Callers must pass only the relevant plaintext part or SMTP diagnostic.
func DecodePayload(text string, maxWireBytes int) (*dns.Msg, error) {
	if maxWireBytes < 12 || maxWireBytes > dns.MaxMsgSize {
		return nil, errors.New("invalid DNS payload limit")
	}
	var payload strings.Builder
	lastErr := errors.New("incomplete base64 DNS payload")
	for i, word := range strings.Fields(text) {
		if i >= 2048 {
			return nil, errors.New("too many base64 chunks")
		}
		for _, c := range word {
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=') {
				return nil, lastErr
			}
		}
		if payload.Len()+len(word) > base64.StdEncoding.EncodedLen(maxWireBytes) {
			return nil, errors.New("DNS payload is too large")
		}
		payload.WriteString(word)
		if payload.Len()%4 != 0 {
			continue
		}
		wire, err := base64.StdEncoding.Strict().DecodeString(payload.String())
		if err != nil {
			return nil, fmt.Errorf("invalid DNS base64: %w", err)
		}
		if len(wire) > maxWireBytes {
			return nil, errors.New("DNS payload is too large")
		}
		m, err := unpackComplete(wire)
		if err == nil {
			return m, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// Msg.Unpack permits trailing bytes. Check the consumed offset using the DNS
// library too, so unrelated text cannot become an ignored base64 suffix.
func unpackComplete(wire []byte) (*dns.Msg, error) {
	if len(wire) < 12 {
		return nil, errors.New("incomplete DNS header")
	}
	m := new(dns.Msg)
	if err := m.Unpack(wire); err != nil {
		return nil, fmt.Errorf("invalid or incomplete DNS packet: %w", err)
	}
	// Unpack accepts a header-only packet even when it declares sections.
	// All declared sections must be present before a wrapped payload is done.
	for i, actual := range []int{len(m.Question), len(m.Answer), len(m.Ns), len(m.Extra)} {
		declared := int(binary.BigEndian.Uint16(wire[4+2*i : 6+2*i]))
		if declared != actual {
			return nil, errors.New("incomplete DNS sections")
		}
	}
	offset := 12
	for range m.Question {
		_, next, err := dns.UnpackDomainName(wire, offset)
		if err != nil || next+4 > len(wire) {
			return nil, errors.New("incomplete DNS question")
		}
		offset = next + 4
	}
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for range section {
			_, next, err := dns.UnpackRR(wire, offset)
			if err != nil {
				return nil, errors.New("incomplete DNS record")
			}
			offset = next
		}
	}
	if offset != len(wire) {
		return nil, errors.New("trailing bytes after DNS packet")
	}
	return m, nil
}
