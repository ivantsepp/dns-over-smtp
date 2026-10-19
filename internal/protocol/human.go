package protocol

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// FormatHumanResponse renders complete records in a single bounded SMTP diagnostic.
func FormatHumanResponse(m *dns.Msg) (string, error) {
	if m == nil || !m.Response || len(m.Question) != 1 {
		return "", errors.New("expected a DNS response with one question")
	}
	const maxDiagnosticBytes = 512 - len("550 5.0.0 \r\n")
	const truncatedNote = "; [truncated]"
	q := m.Question[0]
	status, ok := dns.RcodeToString[m.Rcode]
	if !ok {
		status = fmt.Sprintf("RCODE%d", m.Rcode)
	}
	text := "DNS answer: " + smtpText(q.Name) + " " + dns.Type(q.Qtype).String() + "; status=" + status
	if len(m.Answer) == 0 {
		text += "; no answers"
	}
	if len(text)+len(truncatedNote) > maxDiagnosticBytes {
		return "", errors.New("DNS question cannot fit in SMTP reply")
	}
	truncated := m.Truncated
sections:
	for _, section := range []struct {
		label   string
		records []dns.RR
	}{
		{"", m.Answer},
		{"authority: ", m.Ns},
		{"additional: ", m.Extra},
	} {
		for _, rr := range section.records {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			record := "; " + section.label + smtpText(rr.String())
			if len(text)+len(record)+len(truncatedNote) > maxDiagnosticBytes {
				truncated = true
				break sections
			}
			text += record
		}
	}
	if truncated {
		text += truncatedNote
	}
	return text, nil
}

// DNS names and record data are untrusted, including printable library output.
func smtpText(s string) string {
	var text strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\t':
			text.WriteByte(' ')
		case c < ' ' || c > '~':
			fmt.Fprintf(&text, "\\x%02x", c)
		default:
			text.WriteByte(c)
		}
	}
	return text.String()
}
