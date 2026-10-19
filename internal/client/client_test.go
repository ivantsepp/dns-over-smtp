package client

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"dns-over-smtp/internal/protocol"
	"dns-over-smtp/internal/server"
	gosmtp "github.com/emersion/go-smtp"
	"github.com/miekg/dns"
)

func localBounceServer(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		if q.Question[0].Name == "missing.test." {
			m.Rcode = dns.RcodeNameError
		} else if q.Question[0].Name != "empty.test." {
			rdata := map[uint16]string{
				dns.TypeA:    "A 192.0.2.42",
				dns.TypeAAAA: "AAAA 2001:db8::42",
				dns.TypeMX:   "MX 10 mail.example.test.",
				dns.TypeTXT:  `TXT "hello  world"`,
				dns.TypeCAA:  `CAA 0 issue "ca.example.test"`,
			}[q.Question[0].Qtype]
			rr, err := dns.NewRR(q.Question[0].Name + " 60 IN " + rdata)
			if err != nil {
				t.Error(err)
				return
			}
			m.Answer = []dns.RR{rr}
		}
		w.WriteMsg(m)
	})}
	go upstream.ActivateAndServe()
	t.Cleanup(func() { upstream.Shutdown(); pc.Close() })
	srv, err := server.New(&server.Config{Domain: "localhost", Recipient: "dns@localhost", DNSServer: pc.LocalAddr().String(), QueriesPerMinute: 60}).SMTPServer()
	if err != nil {
		t.Fatal(err)
	}
	return serveSMTP(t, srv)
}

func serveSMTP(t *testing.T, srv *gosmtp.Server) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()
	t.Cleanup(func() { srv.Close(); <-done })
	return l.Addr().String()
}

func directConfig(t *testing.T, addr string) *Config {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := net.LookupPort("tcp", port)
	if err != nil {
		t.Fatal(err)
	}
	return &Config{SMTPHost: host, SMTPPort: p, EmailFrom: "user@local.test", EmailTo: "dns@localhost", Timeout: 3 * time.Second, PollInterval: time.Millisecond}
}

func TestDirectBounceAndConcurrentQueries(t *testing.T) {
	c := New(directConfig(t, localBounceServer(t)))
	var wg sync.WaitGroup
	for _, name := range []string{"one.test.", "two.test.", "missing.test.", "four.test."} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			q := new(dns.Msg)
			q.SetQuestion(name, dns.TypeA)
			m, err := c.Exchange(q)
			if err != nil {
				t.Error(err)
				return
			}
			if err := protocol.ValidateResponse(m, q); err != nil {
				t.Error(err)
			}
			if name == "missing.test." && m.Rcode != dns.RcodeNameError {
				t.Error("lost NXDOMAIN")
			}
			if name != "missing.test." && (len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "192.0.2.42") {
				t.Error("wrong DNS answer")
			}
		}(name)
	}
	wg.Wait()
}

func TestFinalDATARejection(t *testing.T) {
	addr := localBounceServer(t)
	q := new(dns.Msg)
	q.SetQuestion("one.test.", dns.TypeA)
	id, _ := protocol.NewID()
	body, _ := protocol.EncodeQuery(q, id)
	err := smtp.SendMail(addr, nil, "user@local.test", []string{"dns@localhost"}, []byte("Subject: DNS\r\n\r\n"+body+"\r\n"))
	var rejection *textproto.Error
	if !errors.As(err, &rejection) || rejection.Code != 550 {
		t.Fatalf("expected rejection: %v", err)
	}
	if len("550 "+rejection.Msg+"\r\n") > 512 {
		t.Fatal("oversized SMTP reply")
	}
	if _, err := protocol.ParseResponse(rejection.Msg, id); err != nil {
		t.Fatal(err)
	}
	err = smtp.SendMail(addr, nil, "user@local.test", []string{"dns@localhost"}, []byte("Subject: ordinary\r\n\r\nhello\r\n"))
	if !errors.As(err, &rejection) || rejection.Code != 550 || strings.Contains(rejection.Msg, "DNS-RESPONSE:") {
		t.Fatal("ordinary mail was accepted or had an answer")
	}
}

func TestGmailWrappedQueryFinalDATARejection(t *testing.T) {
	raw, err := os.ReadFile("../protocol/testdata/gmail-wrapped.eml")
	if err != nil {
		t.Fatal(err)
	}
	err = smtp.SendMail(localBounceServer(t), nil, "user@local.test", []string{"dns@localhost"}, raw)
	var rejection *textproto.Error
	if !errors.As(err, &rejection) || rejection.Code != 550 {
		t.Fatalf("expected final rejection: %v", err)
	}
	answer, err := protocol.ParseResponse(rejection.Msg, "199fdc8b9f90dd76d04a4669a1e5497b")
	if err != nil {
		t.Fatal(err)
	}
	if answer.Id != 22453 || len(answer.Answer) != 1 || answer.Answer[0].(*dns.A).A.String() != "192.0.2.42" {
		t.Fatalf("wrong answer: %s", answer)
	}
}

func TestBareQueryFinalDATARejection(t *testing.T) {
	addr := localBounceServer(t)
	for _, tc := range []struct {
		body, name string
		rcode      int
	}{
		{"A tseivan.com", "tseivan.com.", dns.RcodeSuccess},
		{"A one.test", "one.test.", dns.RcodeSuccess},
		{"one.test", "one.test.", dns.RcodeSuccess},
		{"DNS-QUERY: A one.test", "one.test.", dns.RcodeSuccess},
		{"\r\n one.test. \r\n\r\n-- \r\nExample Sender", "one.test.", dns.RcodeSuccess},
		{"A one.test\r\n\r\n-- \r\nDNS-QUERY: A other.test", "one.test.", dns.RcodeSuccess},
		{"missing.test", "missing.test.", dns.RcodeNameError},
	} {
		err := smtp.SendMail(addr, nil, "user@local.test", []string{"dns@localhost"}, []byte("Subject: arbitrary subject\r\nContent-Type: text/plain\r\n\r\n"+tc.body+"\r\n"))
		var rejection *textproto.Error
		if !errors.As(err, &rejection) || rejection.Code != 550 {
			t.Fatalf("expected final rejection for %q: %v", tc.body, err)
		}
		if strings.Contains(rejection.Msg, "DNS-RESPONSE:") {
			t.Fatalf("human query returned a base64 wire response: %s", rejection.Msg)
		}
		for _, want := range []string{"DNS answer: " + tc.name + " A", "status=" + dns.RcodeToString[tc.rcode]} {
			if !strings.Contains(rejection.Msg, want) {
				t.Fatalf("manual reply missing %q: %s", want, rejection.Msg)
			}
		}
		if tc.rcode == dns.RcodeSuccess && !strings.Contains(rejection.Msg, "A 192.0.2.42") {
			t.Fatalf("lost manual query result: %s", rejection.Msg)
		}
		if len("550 "+rejection.Msg+"\r\n") > 512 || strings.ContainsAny(rejection.Msg, "\r\n") {
			t.Fatalf("invalid SMTP reply: %q", rejection.Msg)
		}
	}
}

func TestHumanRecordTypesAndMIMEFinalDATARejection(t *testing.T) {
	addr := localBounceServer(t)
	for _, tc := range []struct {
		name, mail, want string
	}{
		{"AAAA", "\r\nAAAA example.test", "AAAA 2001:db8::42"},
		{"MX", "\r\nMX example.test", "MX 10 mail.example.test."},
		{"TXT", "\r\nTXT example.test", `TXT "hello  world"`},
		{"CAA", "\r\nCAA example.test", `CAA 0 issue "ca.example.test"`},
		{"NODATA", "\r\nA empty.test", "status=NOERROR; no answers"},
		{"MIME base64 text", "Content-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte("MX example.test")), "MX 10 mail.example.test."},
		{"MIME alternative", "Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nMX example.test\r\n--b\r\nContent-Type: text/html\r\n\r\n<p>A ignored.test</p>\r\n--b--", "MX 10 mail.example.test."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := smtp.SendMail(addr, nil, "user@local.test", []string{"dns@localhost"}, []byte("Subject: arbitrary\r\n"+tc.mail+"\r\n"))
			var rejection *textproto.Error
			if !errors.As(err, &rejection) || rejection.Code != 550 {
				t.Fatalf("expected final rejection: %v", err)
			}
			if !strings.Contains(rejection.Msg, "DNS answer:") || !strings.Contains(rejection.Msg, tc.want) || strings.Contains(rejection.Msg, "DNS-RESPONSE:") {
				t.Fatalf("wrong human response: %s", rejection.Msg)
			}
		})
	}
}

type acceptingSession struct{}

func (acceptingSession) Reset()                                 {}
func (acceptingSession) Logout() error                          { return nil }
func (acceptingSession) Mail(string, *gosmtp.MailOptions) error { return nil }
func (acceptingSession) Rcpt(string, *gosmtp.RcptOptions) error { return nil }
func (acceptingSession) Data(r io.Reader) error                 { _, err := io.Copy(io.Discard, r); return err }

func TestRelayRequiresInboxAndAuthRequiresTLS(t *testing.T) {
	srv := gosmtp.NewServer(gosmtp.BackendFunc(func(*gosmtp.Conn) (gosmtp.Session, error) { return acceptingSession{}, nil }))
	srv.Domain = "localhost"
	c := New(directConfig(t, serveSMTP(t, srv)))
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	if _, err := c.Exchange(q); err == nil || !strings.Contains(err.Error(), "imap-host") {
		t.Fatalf("relay returned fake answer: %v", err)
	}
	c.config.SMTPUser = "user"
	c.config.SMTPPass = "fixture-password"
	if _, err := c.Exchange(q); err == nil || !strings.Contains(err.Error(), "requires TLS") {
		t.Fatalf("auth attempted without TLS: %v", err)
	}
}

func TestSMTPTimeout(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := l.Accept()
		if err == nil {
			defer conn.Close()
			io.Copy(io.Discard, conn)
		}
	}()
	c := New(directConfig(t, l.Addr().String()))
	c.config.Timeout = 50 * time.Millisecond
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	start := time.Now()
	if _, err := c.Exchange(q); err == nil {
		t.Fatal("hung SMTP succeeded")
	}
	if time.Since(start) > time.Second {
		t.Fatal("timeout ignored")
	}
	<-done
}

func TestMalformedQueryAndCanceledSubmission(t *testing.T) {
	c := New(directConfig(t, "127.0.0.1:1"))
	if _, err := c.Exchange(new(dns.Msg)); err == nil {
		t.Fatal("accepted empty question")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.submit(ctx, "", ""); err == nil {
		t.Fatal("ignored canceled context")
	}
}
