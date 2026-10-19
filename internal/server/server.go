package server

import (
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/mail"
	"strings"
	"sync"
	"time"

	"dns-over-smtp/internal/guard"
	"dns-over-smtp/internal/protocol"
	"github.com/emersion/go-smtp"
	"github.com/miekg/dns"
	"golang.org/x/net/netutil"
)

type Config struct {
	ListenAddr       string
	Domain           string
	Recipient        string
	DNSServer        string
	TLSCert          string
	TLSKey           string
	QueriesPerMinute int
}

type peerWindow struct {
	start time.Time
	count int
}

type Server struct {
	config        *Config
	mu            sync.Mutex
	peers         map[string]peerWindow
	resolverSlots chan struct{}
	breaker       guard.Breaker
}

func New(config *Config) *Server {
	return &Server{config: config, peers: make(map[string]peerWindow), resolverSlots: make(chan struct{}, 16)}
}

func (s *Server) SMTPServer() (*smtp.Server, error) {
	if s.config.Domain == "" || strings.ContainsAny(s.config.Domain, "\r\n \t") {
		return nil, errors.New("a valid SMTP hostname is required")
	}
	addr, err := mail.ParseAddress(s.config.Recipient)
	if err != nil || addr.Address != s.config.Recipient {
		return nil, errors.New("a plain demo recipient address is required")
	}
	if _, _, err := net.SplitHostPort(s.config.DNSServer); err != nil {
		return nil, errors.New("DNS upstream must have host:port form")
	}
	if s.config.QueriesPerMinute < 1 {
		return nil, errors.New("queries-per-minute must be positive")
	}
	if (s.config.TLSCert == "") != (s.config.TLSKey == "") {
		return nil, errors.New("tls-cert and tls-key must be supplied together")
	}
	srv := smtp.NewServer(s)
	srv.ErrorLog = guard.EventLogger{Event: "smtp_session_error"}
	srv.Addr = s.config.ListenAddr
	srv.Domain = s.config.Domain
	srv.MaxRecipients = 1
	srv.MaxMessageBytes = protocol.MaxMailBytes
	srv.MaxLineLength = 1000
	srv.ReadTimeout = 20 * time.Second
	srv.WriteTimeout = 20 * time.Second
	if s.config.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(s.config.TLSCert, s.config.TLSKey)
		if err != nil {
			return nil, err
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	return srv, nil
}

func (s *Server) Start() error {
	srv, err := s.SMTPServer()
	if err != nil {
		return err
	}
	l, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return err
	}
	defer l.Close()
	slog.Info("smtp_listener_started", "listen", l.Addr().String())
	return srv.Serve(netutil.LimitListener(l, 64))
}

func (s *Server) NewSession(c *smtp.Conn) (smtp.Session, error) {
	peer, _, err := net.SplitHostPort(c.Conn().RemoteAddr().String())
	if err != nil {
		return nil, reject("Invalid peer")
	}
	return &session{server: s, peer: peer}, nil
}

func (s *Server) allow(peer string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, entry := range s.peers {
		if now.Sub(entry.start) >= time.Minute {
			delete(s.peers, key)
		}
	}
	w, exists := s.peers[peer]
	if !exists {
		if len(s.peers) >= 4096 {
			return false
		}
		w.start = now
	}
	w.count++
	s.peers[peer] = w
	return w.count <= s.config.QueriesPerMinute
}

type session struct {
	server *Server
	peer   string
}

func (s *session) Reset()        {}
func (s *session) Logout() error { return nil }
func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	// A null reverse path cannot receive a bounce and could create a loop.
	if from == "" {
		return reject("A nonempty return address is required for DNS queries")
	}
	return nil
}
func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	if !strings.EqualFold(to, s.server.config.Recipient) {
		return reject("Unknown demo recipient")
	}
	return nil
}

func (s *session) Data(r io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(r, protocol.MaxMailBytes+1))
	if err != nil || len(raw) > protocol.MaxMailBytes {
		return reject("Message too large or unreadable")
	}
	if !s.server.allow(s.peer) {
		return reject("DNS query rate limit exceeded")
	}
	request, err := protocol.ParseRequest(raw)
	if err != nil {
		slog.Info("smtp_invalid_query_rejected")
		return reject("Invalid DNS query; put A example.com or example.com in the email body")
	}
	response, err := s.server.Resolve(request.Query)
	if err != nil {
		slog.Warn("dns_upstream_failure", "request_id", request.ID)
		response = new(dns.Msg)
		response.SetRcode(request.Query, dns.RcodeServerFailure)
	}
	var diagnostic string
	if request.HumanReadable {
		diagnostic, err = protocol.FormatHumanResponse(response)
	} else {
		diagnostic, err = protocol.EncodeResponse(response, request.ID)
	}
	if err != nil {
		return reject("DNS answer cannot fit in a bounce")
	}
	slog.Info("smtp_dns_answer_rejected", "request_id", request.ID, "rcode", response.Rcode)
	return reject(diagnostic)
}

func reject(message string) *smtp.SMTPError {
	return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 0, 0}, Message: message}
}

func (s *Server) Resolve(query *dns.Msg) (response *dns.Msg, err error) {
	if err = protocol.ValidateQuery(query); err != nil {
		return nil, err
	}
	if !s.breaker.Allow() {
		return nil, errors.New("DNS upstream circuit is open")
	}
	select {
	case s.resolverSlots <- struct{}{}:
		defer func() { <-s.resolverSlots }()
	default:
		return nil, errors.New("DNS upstream is busy")
	}
	defer func() { s.breaker.Record(err) }()
	c := &dns.Client{Timeout: 3 * time.Second}
	response, _, err = c.Exchange(query, s.config.DNSServer)
	if err == nil && response.Truncated {
		c.Net = "tcp"
		response, _, err = c.Exchange(query, s.config.DNSServer)
	}
	if err == nil {
		err = protocol.ValidateResponse(response, query)
	}
	return response, err
}
