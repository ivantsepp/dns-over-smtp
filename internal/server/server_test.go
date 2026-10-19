package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/emersion/go-smtp"
)

func TestHumanQueryUpstreamFailure(t *testing.T) {
	s := New(&Config{Recipient: "dns@localhost", QueriesPerMinute: 60})
	// Open the circuit without a slow or external resolver connection.
	for i := 0; i < 5; i++ {
		s.breaker.Record(errors.New("resolver unavailable"))
	}
	session := &session{server: s, peer: "127.0.0.1"}
	err := session.Data(strings.NewReader("Subject: manual\r\n\r\nA example.test\r\n"))
	rejection, ok := err.(*smtp.SMTPError)
	if !ok || rejection.Code != 550 || !strings.Contains(rejection.Message, "DNS answer: example.test. A; status=SERVFAIL; no answers") || strings.Contains(rejection.Message, "DNS-RESPONSE:") {
		t.Fatalf("upstream failure lost human format: %v", err)
	}
}

func TestServerValidation(t *testing.T) {
	config := &Config{Domain: "localhost", Recipient: "dns@localhost", DNSServer: "127.0.0.1:53", QueriesPerMinute: 2}
	s := New(config)
	if _, err := s.SMTPServer(); err != nil {
		t.Fatal(err)
	}
	config.TLSCert = "certificate.pem"
	if _, err := s.SMTPServer(); err == nil {
		t.Fatal("accepted unpaired TLS files")
	}
	config.TLSCert = ""
	config.Recipient = "bad\r\naddress"
	if _, err := s.SMTPServer(); err == nil {
		t.Fatal("accepted injected address")
	}
}

func TestRejectsMailAndLimitsPeer(t *testing.T) {
	s := New(&Config{Recipient: "dns@localhost", QueriesPerMinute: 2})
	session := &session{server: s, peer: "127.0.0.1"}
	if session.Mail("", nil) == nil {
		t.Fatal("accepted null reverse path")
	}
	if session.Rcpt("other@localhost", nil) == nil {
		t.Fatal("accepted another recipient")
	}
	if session.Rcpt("dns@localhost", nil) != nil {
		t.Fatal("rejected configured recipient")
	}
	err := session.Data(strings.NewReader("Subject: hello\r\n\r\nordinary email\r\n"))
	if e, ok := err.(*smtp.SMTPError); !ok || e.Code != 550 {
		t.Fatalf("ordinary mail accepted: %v", err)
	}
	if !s.allow("127.0.0.1") || s.allow("127.0.0.1") {
		t.Fatal("rate limit failed")
	}
	if !s.allow("127.0.0.2") {
		t.Fatal("limited a different peer")
	}
}
