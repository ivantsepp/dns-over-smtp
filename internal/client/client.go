package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"

	"dns-over-smtp/internal/guard"
	"dns-over-smtp/internal/protocol"
	"github.com/miekg/dns"
)

type Config struct {
	SMTPHost        string
	SMTPPort        int
	SMTPUser        string
	SMTPPass        string
	SMTPImplicitTLS bool
	EmailFrom       string
	EmailTo         string
	ListenAddr      string
	IMAPHost        string
	IMAPPort        int
	IMAPUser        string
	IMAPPass        string
	IMAPMailbox     string
	Timeout         time.Duration
	PollInterval    time.Duration
	// Optional additional trust roots, e.g. for a private mail server.
	TLSRootCAs *x509.CertPool
}

type Client struct {
	config  *Config
	slots   chan struct{}
	breaker guard.Breaker
}

func New(config *Config) *Client {
	return &Client{config: config, slots: make(chan struct{}, 8)}
}

func (c *Client) Validate() error {
	if c.config.Timeout <= 0 || c.config.PollInterval <= 0 {
		return errors.New("timeout and poll-interval must be positive")
	}
	if c.config.SMTPHost == "" || c.config.SMTPPort < 1 || c.config.SMTPPort > 65535 {
		return errors.New("valid SMTP host and port required")
	}
	for _, value := range []string{c.config.EmailFrom, c.config.EmailTo} {
		a, err := mail.ParseAddress(value)
		if err != nil || a.Address != value || strings.ContainsAny(value, "\r\n") {
			return errors.New("plain email-from and email-to addresses required")
		}
	}
	if (c.config.SMTPUser == "") != (c.config.SMTPPass == "") {
		return errors.New("smtp-user and smtp-pass must be supplied together")
	}
	if c.config.IMAPHost != "" && (c.config.IMAPUser == "" || c.config.IMAPPass == "" || c.config.IMAPPort < 1 || c.config.IMAPPort > 65535 || c.config.IMAPMailbox == "") {
		return errors.New("valid IMAP port, user, password and mailbox required")
	}
	return nil
}

func (c *Client) Start() error {
	if err := c.Validate(); err != nil {
		return err
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", c.handleDNSQuery)
	s := &dns.Server{Addr: c.config.ListenAddr, Net: "udp", Handler: mux}
	slog.Info("dns_listener_started", "listen", c.config.ListenAddr)
	return s.ListenAndServe()
}

func (c *Client) handleDNSQuery(w dns.ResponseWriter, query *dns.Msg) {
	answer, err := c.Exchange(query)
	if err != nil {
		slog.Warn("dns_query_failed")
		answer = new(dns.Msg)
		answer.SetRcode(query, dns.RcodeServerFailure)
	}
	if err := w.WriteMsg(answer); err != nil {
		slog.Warn("dns_reply_write_failed")
	}
}

// Exchange accepts the intentional rejection as success, or waits for its DSN.
func (c *Client) Exchange(query *dns.Msg) (answer *dns.Msg, err error) {
	if err = c.Validate(); err != nil {
		return nil, err
	}
	if err = protocol.ValidateQuery(query); err != nil {
		return nil, err
	}
	if !c.breaker.Allow() {
		return nil, errors.New("mail transport circuit is open; try again later")
	}
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return nil, errors.New("too many pending DNS queries")
	}
	defer func() { c.breaker.Record(err) }()
	id, err := protocol.NewID()
	if err != nil {
		return nil, err
	}
	body, err := protocol.EncodeQuery(query, id)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.config.Timeout)
	defer cancel()
	var inbox *inbox
	if c.config.IMAPHost != "" {
		inbox, err = c.openInbox(ctx)
		if err != nil {
			return nil, err
		}
		defer inbox.close()
	}
	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: DNS Query %s\r\nMessage-ID: <%s@dns-over-smtp.invalid>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\nContent-Transfer-Encoding: 7bit\r\n\r\n%s\r\n", c.config.EmailFrom, c.config.EmailTo, id, id, body)
	answer, err = c.submit(ctx, message, id)
	if err != nil {
		return nil, err
	}
	if answer == nil {
		if inbox == nil {
			return nil, errors.New("SMTP relay accepted the query; configure -imap-host to retrieve the bounce")
		}
		slog.Info("dns_bounce_waiting", "request_id", id)
		answer, err = inbox.wait(ctx, id, c.config.PollInterval)
		if err != nil {
			return nil, err
		}
	}
	if err = protocol.ValidateResponse(answer, query); err != nil {
		return nil, err
	}
	slog.Info("dns_answer_received", "request_id", id, "rcode", answer.Rcode)
	return answer, nil
}

func (c *Client) submit(ctx context.Context, message, id string) (*dns.Msg, error) {
	addr := net.JoinHostPort(c.config.SMTPHost, fmt.Sprint(c.config.SMTPPort))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connect SMTP: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{ServerName: c.config.SMTPHost, MinVersion: tls.VersionTLS12, RootCAs: c.config.TLSRootCAs}
	var transport net.Conn = conn
	if c.config.SMTPImplicitTLS {
		t := tls.Client(conn, tlsConfig)
		if err := t.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		transport = t
	}
	s, err := smtp.NewClient(transport, c.config.SMTPHost)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if !c.config.SMTPImplicitTLS {
		if ok, _ := s.Extension("STARTTLS"); ok {
			if err := s.StartTLS(tlsConfig); err != nil {
				return nil, err
			}
		} else if c.config.SMTPUser != "" {
			return nil, errors.New("SMTP authentication requires TLS")
		}
	}
	if c.config.SMTPUser != "" {
		if err := s.Auth(smtp.PlainAuth("", c.config.SMTPUser, c.config.SMTPPass, c.config.SMTPHost)); err != nil {
			return nil, errors.New("SMTP authentication failed")
		}
	}
	if err := s.Mail(c.config.EmailFrom); err != nil {
		return nil, err
	}
	if err := s.Rcpt(c.config.EmailTo); err != nil {
		return nil, err
	}
	w, err := s.Data()
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(w, message); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		var rejection *textproto.Error
		if !errors.As(err, &rejection) || rejection.Code != 550 {
			return nil, err
		}
		answer, parseErr := protocol.ParseResponse(rejection.Msg, id)
		if parseErr != nil {
			return nil, fmt.Errorf("SMTP rejection did not contain a valid matching DNS answer: %w", parseErr)
		}
		return answer, nil
	}
	return nil, nil
}
