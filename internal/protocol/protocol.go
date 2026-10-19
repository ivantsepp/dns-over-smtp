// Package protocol defines the bounded query and rejection payloads.
package protocol

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"regexp"
	"strings"

	"github.com/miekg/dns"
)

const (
	MaxMailBytes  = 64 * 1024
	MaxQueryBytes = 512
	// Leave space for the status code, correlation ID and base64 overhead.
	MaxResponseBytes = 300
)

var ErrNoResponse = errors.New("no DNS answer in bounce")
var replyPattern = regexp.MustCompile(`DNS-RESPONSE:\s+([a-f0-9]{32})\s+`)
var bareDomainPattern = regexp.MustCompile(`(?i)^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+\.?$`)

func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func validID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 16 && id == strings.ToLower(id)
}

func ValidateQuery(m *dns.Msg) error {
	if m.Response || m.Opcode != dns.OpcodeQuery || len(m.Question) != 1 {
		return errors.New("expected one standard DNS question")
	}
	q := m.Question[0]
	if _, ok := dns.IsDomainName(q.Name); !ok || q.Qclass != dns.ClassINET {
		return errors.New("invalid DNS name or class")
	}
	switch q.Qtype {
	case 0, dns.TypeOPT, dns.TypeTKEY, dns.TypeTSIG, dns.TypeIXFR, dns.TypeAXFR, dns.TypeMAILA, dns.TypeMAILB, dns.TypeANY, dns.TypeReserved:
		return errors.New("transfer, ANY, meta and reserved queries are unsupported")
	}
	if len(m.Answer) != 0 || len(m.Ns) != 0 {
		return errors.New("query contains answer records")
	}
	if len(m.Extra) > 1 {
		return errors.New("too many additional query records")
	}
	if len(m.Extra) == 1 {
		opt, ok := m.Extra[0].(*dns.OPT)
		if !ok || opt.Hdr.Name != "." || opt.Version() != 0 {
			return errors.New("only EDNS version zero is supported")
		}
	}
	if b, err := m.Pack(); err != nil || len(b) > MaxQueryBytes {
		return errors.New("DNS query is too large or invalid")
	}
	return nil
}

func EncodeQuery(m *dns.Msg, id string) (string, error) {
	if !validID(id) {
		return "", errors.New("invalid request ID")
	}
	if err := ValidateQuery(m); err != nil {
		return "", err
	}
	b, err := m.Pack()
	if err != nil {
		return "", err
	}
	if len(b) > MaxQueryBytes {
		return "", errors.New("DNS query is too large")
	}
	payload := base64.StdEncoding.EncodeToString(b)
	var body strings.Builder
	body.WriteString("DNS-QUERY: " + id)
	for len(payload) > 0 {
		n := min(64, len(payload))
		body.WriteString("\r\n" + payload[:n])
		payload = payload[n:]
	}
	return body.String(), nil
}

// ParseQuery accepts tagged queries or a first-line "A example.com" / "example.com".
func ParseQuery(raw []byte) (*dns.Msg, string, error) {
	parts, err := emailParts(raw)
	if err != nil {
		return nil, "", err
	}
	var firstLines []string
	for _, p := range parts {
		if p.mediaType != "text/plain" {
			continue
		}
		for _, line := range strings.Split(p.body, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				firstLines = append(firstLines, line)
				break
			}
		}
	}
	// A valid bare first line selects the query before later signature markers.
	if len(firstLines) > 0 && !strings.HasPrefix(firstLines[0], "DNS-QUERY:") {
		if query, id, err := parseBareQuery(firstLines[0]); err == nil {
			if len(firstLines) != 1 {
				return nil, "", errors.New("expected one nonempty plain-text query body")
			}
			return query, id, nil
		}
	}
	var queryText string
	found := false
	for _, p := range parts {
		if p.mediaType != "text/plain" {
			continue
		}
		lines := strings.Split(p.body, "\n")
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "DNS-QUERY:") {
				if found {
					return nil, "", errors.New("multiple DNS queries in message")
				}
				found = true
				head := strings.TrimPrefix(line, "DNS-QUERY:")
				queryText = head + "\n" + strings.Join(lines[i+1:], "\n")
			}
		}
	}
	if !found {
		if len(firstLines) != 1 {
			return nil, "", errors.New("expected one nonempty plain-text query body")
		}
		return parseBareQuery(firstLines[0])
	}
	fields := strings.Fields(queryText)
	if len(fields) < 2 {
		return nil, "", errors.New("expected DNS-QUERY: <request-id> <base64> or <type> <name>")
	}
	m := new(dns.Msg)
	id := fields[0]
	if qtype, ok := dns.StringToType[strings.ToUpper(fields[0])]; ok {
		var declaration []string
		for _, line := range strings.Split(queryText, "\n") {
			declaration = append(declaration, strings.Fields(line)...)
			if len(declaration) >= 2 {
				break
			}
		}
		if len(declaration) != 2 {
			return nil, "", errors.New("expected DNS-QUERY: <type> <name>")
		}
		m.SetQuestion(dns.Fqdn(fields[1]), qtype)
		id, err = NewID()
		if err != nil {
			return nil, "", err
		}
	} else {
		if !validID(id) {
			return nil, "", errors.New("invalid or oversized query payload")
		}
		m, err = DecodePayload(strings.Join(fields[1:], " "), MaxQueryBytes)
		if err != nil {
			return nil, "", err
		}
	}
	return m, id, ValidateQuery(m)
}

func parseBareQuery(line string) (*dns.Msg, string, error) {
	fields := strings.Fields(line)
	qtype := uint16(dns.TypeA)
	var name string
	switch len(fields) {
	case 1:
		// Require a dotted name so greetings and prose do not trigger lookups.
		if !bareDomainPattern.MatchString(fields[0]) {
			return nil, "", errors.New("expected a dotted domain on the first nonblank body line")
		}
		name = fields[0]
	case 2:
		var ok bool
		qtype, ok = dns.StringToType[strings.ToUpper(fields[0])]
		if !ok {
			return nil, "", errors.New("unknown DNS record type")
		}
		name = fields[1]
	default:
		return nil, "", errors.New("expected <type> <name> or a domain on the first nonblank body line")
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	if err := ValidateQuery(m); err != nil {
		return nil, "", err
	}
	id, err := NewID()
	if err != nil {
		return nil, "", err
	}
	return m, id, nil
}

func EncodeResponse(m *dns.Msg, id string) (string, error) {
	if !validID(id) || !m.Response {
		return "", errors.New("invalid DNS response or request ID")
	}
	m = m.Copy()
	m.Compress = true
	var b []byte
	for {
		var err error
		b, err = m.Pack()
		if err != nil {
			return "", err
		}
		if len(b) <= MaxResponseBytes {
			break
		}
		removed := false
		for _, section := range []*[]dns.RR{&m.Extra, &m.Ns, &m.Answer} {
			for i := len(*section) - 1; i >= 0; i-- {
				if (*section)[i].Header().Rrtype == dns.TypeOPT {
					continue
				}
				h := (*section)[i].Header()
				kept := (*section)[:0]
				for _, rr := range *section {
					rh := rr.Header()
					if !strings.EqualFold(rh.Name, h.Name) || rh.Rrtype != h.Rrtype || rh.Class != h.Class {
						kept = append(kept, rr)
					}
				}
				*section = kept
				removed = true
				break
			}
			if removed {
				break
			}
		}
		if !removed {
			if opt := m.IsEdns0(); opt != nil && len(opt.Option) > 0 {
				opt.Option = nil
				removed = true
			}
		}
		if !removed {
			return "", errors.New("DNS question cannot fit in SMTP reply")
		}
		m.Truncated = true
	}
	payload := "DNS-RESPONSE: " + id + " " + base64.StdEncoding.EncodeToString(b)
	summary := " [" + dns.RcodeToString[m.Rcode]
	if m.Truncated {
		summary += " TC=1"
	}
	if len(m.Answer) > 0 {
		switch rr := m.Answer[0].(type) {
		case *dns.A:
			summary += " A=" + rr.A.String()
		case *dns.AAAA:
			summary += " AAAA=" + rr.AAAA.String()
		}
	}
	summary += "]"
	if len("550 5.0.0 "+payload+summary+"\r\n") <= 512 {
		payload += summary
	}
	return payload, nil
}

// ParseResponse parses a server diagnostic, including folded DSN whitespace.
// expectedID can be empty when decoding a saved bounce manually.
func ParseResponse(diagnostic, expectedID string) (*dns.Msg, error) {
	for _, match := range replyPattern.FindAllStringSubmatchIndex(diagnostic, -1) {
		id := diagnostic[match[2]:match[3]]
		if expectedID != "" && id != expectedID {
			continue
		}
		m, err := DecodePayload(diagnostic[match[1]:], MaxResponseBytes)
		if err != nil {
			return nil, err
		}
		if !m.Response || m.Opcode != dns.OpcodeQuery || len(m.Question) != 1 {
			return nil, errors.New("invalid DNS response header")
		}
		return m, nil
	}
	return nil, ErrNoResponse
}

// ParseBounce reads actual DSN diagnostics, never the attached original email.
func ParseBounce(raw []byte, expectedID string) (*dns.Msg, error) {
	parts, err := emailParts(raw)
	if err != nil {
		return nil, err
	}
	for _, p := range parts {
		if p.mediaType != "message/delivery-status" {
			continue
		}
		reader := textproto.NewReader(bufio.NewReader(strings.NewReader(p.body)))
		for {
			h, err := reader.ReadMIMEHeader()
			if err == io.EOF && len(h) == 0 {
				break
			}
			if err != nil && err != io.EOF {
				return nil, fmt.Errorf("invalid delivery-status block: %w", err)
			}
			value := h.Get("Diagnostic-Code")
			kind, diagnostic, ok := strings.Cut(value, ";")
			if !ok || !strings.EqualFold(strings.TrimSpace(kind), "smtp") || h.Get("Action") != "failed" {
				continue
			}
			diagnostic = strings.TrimSpace(diagnostic)
			if !strings.HasPrefix(diagnostic, "550 ") {
				continue
			}
			m, err := ParseResponse(diagnostic, expectedID)
			if !errors.Is(err, ErrNoResponse) {
				return m, err
			}
		}
	}
	return nil, ErrNoResponse
}

func ValidateResponse(response, query *dns.Msg) error {
	if !response.Response || response.Id != query.Id || response.Opcode != query.Opcode || len(response.Question) != 1 {
		return errors.New("DNS response does not match query")
	}
	a, b := response.Question[0], query.Question[0]
	if !strings.EqualFold(a.Name, b.Name) || a.Qtype != b.Qtype || a.Qclass != b.Qclass {
		return errors.New("DNS response question does not match query")
	}
	return nil
}

type emailPart struct{ mediaType, body string }

func emailParts(raw []byte) ([]emailPart, error) {
	if len(raw) > MaxMailBytes {
		return nil, errors.New("email is too large")
	}
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid email: %w", err)
	}
	var parts []emailPart
	err = walkMIME(textproto.MIMEHeader(m.Header), m.Body, 0, &parts)
	return parts, err
}

func walkMIME(h textproto.MIMEHeader, r io.Reader, depth int, parts *[]emailPart) error {
	if depth > 8 || len(*parts) >= 32 {
		return errors.New("email MIME structure is too complex")
	}
	contentType := h.Get("Content-Type")
	if contentType == "" {
		contentType = "text/plain"
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return err
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		if params["boundary"] == "" {
			return errors.New("missing MIME boundary")
		}
		mr := multipart.NewReader(r, params["boundary"])
		for {
			p, err := mr.NextRawPart()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if err := walkMIME(p.Header, p, depth+1, parts); err != nil {
				return err
			}
		}
	}
	// Do not recursively inspect message/rfc822 attachments.
	if mediaType != "text/plain" && mediaType != "message/delivery-status" {
		return nil
	}
	switch strings.ToLower(h.Get("Content-Transfer-Encoding")) {
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, r)
	case "quoted-printable":
		r = quotedprintable.NewReader(r)
	case "", "7bit", "8bit", "binary":
	default:
		return errors.New("unsupported content transfer encoding")
	}
	b, err := io.ReadAll(io.LimitReader(r, MaxMailBytes+1))
	if err != nil {
		return err
	}
	if len(b) > MaxMailBytes {
		return errors.New("decoded MIME part is too large")
	}
	*parts = append(*parts, emailPart{mediaType, string(b)})
	return nil
}
